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
use elastos_protected_content_provider_contracts::MAX_OBJECT_FRAMED_CHUNK_BYTES_V1;
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
    write_owner_only_bytes, InactiveCustodyProvider, MediaToolsTrust, ObjectFramedStagingSink,
    RuntimeCustodyAttemptConflict, RuntimeCustodyAttemptConflictReason, RuntimeCustodyComposition,
    RuntimeCustodyCompositionConfigFile, RuntimeCustodyConfirmedPurchaseStage,
    RuntimeCustodyLibraryPublishInput, RuntimeCustodyLibraryPublishObjectInput,
    RuntimeCustodyLibrarySourceInput, RuntimeCustodyPurchaseAccessEvidenceRecord,
    RuntimeCustodyPurchaseProgress, RuntimeCustodyPurchaseRecord,
    RuntimeCustodyPurchaseStageRecord, RuntimeCustodyRegistryAdapter,
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

const TEST_VIEWER_LAUNCH_ID: &str = "launch:11111111111111111111111111111111";
const TEST_VIEWER_LAUNCH_ID_B: &str = "launch:22222222222222222222222222222222";
/// Every existing test in this file exercises the media/player viewer path;
/// session binding v3 takes the verified executable actor as an explicit
/// parameter instead of a hard-coded constant, so these tests supply the same
/// value the real player launch context would carry.
const TEST_VIEWER_EXECUTABLE_ACTOR: &str = "elacity-player";
/// The second viewer capsule session binding v3 admits. Used to prove the
/// kind <-> viewer check denies it on a media mint.
const TEST_VIEWER_READER_EXECUTABLE_ACTOR: &str = "elacity-reader";

struct RecordingProvider {
    name: &'static str,
    requests: Mutex<Vec<Value>>,
    response: Value,
}

struct SequencedProvider {
    name: &'static str,
    requests: Mutex<Vec<Value>>,
    responses: Mutex<VecDeque<Result<Value, ProviderError>>>,
}

struct PrepareOnlyCleanupDecryptProvider {
    expected_issuer_seed: u8,
    requests: Mutex<Vec<Value>>,
}

struct ProcessChainEvidenceProvider {
    expected_request: RightsProviderRequestV1,
    requests: Mutex<Vec<Value>>,
    has_access: bool,
}

/// One rendition a test media provider prepares: what it declares and how many
/// segments it writes. A test declares a wrong pair on purpose to see it refused.
#[cfg(unix)]
#[derive(Clone, Copy)]
struct TestPreparedRendition {
    kind: CencDashRenditionKindV2,
    mime_type: &'static str,
    codecs: &'static str,
    segments: usize,
}

#[cfg(unix)]
const TEST_PREPARED_VIDEO: TestPreparedRendition = TestPreparedRendition {
    kind: media_dash_fixture::V,
    mime_type: "video/mp4",
    codecs: "avc1.640028",
    segments: 2,
};

#[cfg(unix)]
const TEST_PREPARED_AUDIO: TestPreparedRendition = TestPreparedRendition {
    kind: media_dash_fixture::A,
    mime_type: "audio/mp4",
    codecs: "mp4a.40.2",
    segments: 2,
};

#[cfg(unix)]
#[derive(Clone, Copy)]
enum TestMediaPreparationResponse {
    Prepared(&'static [TestPreparedRendition]),
    SettledFailure,
    UnknownSettlement,
}

#[cfg(unix)]
impl TestMediaPreparationResponse {
    const fn prepared_video_audio() -> Self {
        Self::Prepared(&[TEST_PREPARED_VIDEO, TEST_PREPARED_AUDIO])
    }

    const fn prepared_video() -> Self {
        Self::Prepared(&[TEST_PREPARED_VIDEO])
    }

    const fn prepared_audio() -> Self {
        Self::Prepared(&[TEST_PREPARED_AUDIO])
    }
}

#[cfg(unix)]
struct TestMediaPreparationProvider {
    staging_root: PathBuf,
    requests: Mutex<Vec<String>>,
    response: TestMediaPreparationResponse,
}

#[cfg(unix)]
const TEST_CUSTODY_PROVIDER_BIN_ENV: &str = "ELASTOS_TEST_CUSTODY_PROVIDER_BIN";
#[cfg(unix)]
const TEST_DECRYPT_PROVIDER_BIN_ENV: &str = "ELASTOS_TEST_DECRYPT_PROVIDER_BIN";
#[cfg(unix)]
const TEST_PROTECT_PROVIDER_BIN_ENV: &str = "ELASTOS_TEST_PROTECT_PROVIDER_BIN";

#[derive(Clone)]
struct ContentAvailabilityTestConfig {
    policy: String,
    status: String,
    replicas: u32,
    live_multi_peer_proof: Option<bool>,
    checked_at: u64,
    receipt_cid: Option<String>,
    receipt_object_identity: Option<String>,
    receipt_publisher_did: Option<String>,
    malformed_receipt: bool,
    mutate_fetch_path: Option<String>,
    mutate_manifest_extra_file: bool,
}

impl ContentAvailabilityTestConfig {
    fn accepted() -> Self {
        Self {
            policy: "protected-content-replication/v1".to_string(),
            status: "network_available".to_string(),
            replicas: 3,
            live_multi_peer_proof: Some(true),
            checked_at: NOW,
            receipt_cid: None,
            receipt_object_identity: None,
            receipt_publisher_did: None,
            malformed_receipt: false,
            mutate_fetch_path: None,
            mutate_manifest_extra_file: false,
        }
    }

    fn accepted_now() -> Self {
        Self::accepted_at(crate::auth::now_ts())
    }

    fn accepted_at(checked_at: u64) -> Self {
        Self {
            checked_at,
            ..Self::accepted()
        }
    }
}

struct ContentAvailabilityTestProvider {
    signing_key: SigningKey,
    config: ContentAvailabilityTestConfig,
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    manifest: Mutex<Option<crate::content::ContentObjectManifest>>,
    requests: Mutex<Vec<Value>>,
}

impl ContentAvailabilityTestProvider {
    const CID: &'static str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

    fn new(seed: u8, config: ContentAvailabilityTestConfig) -> Arc<Self> {
        Self::with_signing_key(elastos_identity::derive_did(&[seed; 32]).0, config)
    }

    fn with_signing_key(
        signing_key: SigningKey,
        config: ContentAvailabilityTestConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            signing_key,
            config,
            files: Mutex::new(BTreeMap::new()),
            manifest: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn signer_did(&self) -> String {
        crate::crypto::domain_separated_sign(
            &self.signing_key,
            "elastos.content.availability.receipt.v1",
            b"content-availability-test-provider",
        )
        .1
    }

    async fn publish(&self, request: &Value) -> Result<Value, ProviderError> {
        let object_identity = request
            .get("object_did")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing object identity".to_string()))?;
        let publisher_did = request
            .get("publisher_did")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing publisher identity".to_string()))?;
        if request.get("object_kind").and_then(Value::as_str) != Some("protected-content") {
            return Err(ProviderError::Provider("wrong object kind".to_string()));
        }
        let entries = request
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| ProviderError::Provider("missing files".to_string()))?;
        let mut stored = BTreeMap::new();
        let mut manifest_files = Vec::with_capacity(entries.len());
        for entry in entries {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| ProviderError::Provider("bad file path".to_string()))?;
            let bytes = entry
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| ProviderError::Provider("missing file data".to_string()))
                .and_then(|encoded| {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|_| ProviderError::Provider("bad file data".to_string()))
                })?;
            if stored.insert(path.to_string(), bytes.clone()).is_some() {
                return Err(ProviderError::Provider("duplicate file".to_string()));
            }
            manifest_files.push(crate::content::ContentObjectFile {
                path: path.to_string(),
                sha256: hex::encode(sha2::Sha256::digest(&bytes)),
                size: bytes.len() as u64,
            });
        }
        manifest_files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = crate::content::ContentObjectManifest {
            schema: "elastos.content.object.manifest/v1".to_string(),
            kind: "protected-content".to_string(),
            content_digest: super::content_object_digest(&manifest_files),
            files: manifest_files,
            links: Vec::new(),
            object_did: Some(object_identity.to_string()),
            publisher_did: Some(publisher_did.to_string()),
        };
        stored.insert(
            crate::content::CONTENT_OBJECT_MANIFEST_PATH.to_string(),
            serde_json::to_vec(&manifest)
                .map_err(|_| ProviderError::Provider("manifest encode failed".to_string()))?,
        );
        *self.files.lock().await = stored;
        *self.manifest.lock().await = Some(manifest);
        Ok(ok_provider_response(json!({ "cid": Self::CID })))
    }

    async fn status(&self) -> Result<Value, ProviderError> {
        if self.config.malformed_receipt {
            return Ok(ok_provider_response(json!({
                "receipt": {
                    "payload": "malformed",
                },
            })));
        }
        let manifest = self
            .manifest
            .lock()
            .await
            .clone()
            .ok_or_else(|| ProviderError::Provider("missing published object".to_string()))?;
        let object_identity = self
            .config
            .receipt_object_identity
            .as_deref()
            .or(manifest.object_did.as_deref())
            .ok_or_else(|| ProviderError::Provider("missing object identity".to_string()))?;
        let publisher_did = self
            .config
            .receipt_publisher_did
            .as_deref()
            .or(manifest.publisher_did.as_deref())
            .ok_or_else(|| ProviderError::Provider("missing publisher identity".to_string()))?;
        let cid = self.config.receipt_cid.as_deref().unwrap_or(Self::CID);
        let payload = crate::content::AvailabilityReceipt {
            schema: "elastos.content.availability.receipt/v1".to_string(),
            cid: cid.to_string(),
            uri: format!("elastos://{cid}"),
            object_did: Some(object_identity.to_string()),
            publisher_did: publisher_did.to_string(),
            provider: "content".to_string(),
            policy: self.config.policy.clone(),
            status: self.config.status.clone(),
            replicas: self.config.replicas,
            peer_selection: self
                .config
                .live_multi_peer_proof
                .map(|live_multi_peer_proof| {
                    json!({
                        "live_multi_peer_proof": live_multi_peer_proof,
                    })
                })
                .unwrap_or_else(|| json!({})),
            quota: json!({}),
            repair_worker: json!({}),
            storage_market: json!({}),
            repair_graph: json!({}),
            abuse_controls: json!({}),
            accounting: json!({}),
            checked_at: self.config.checked_at,
        };
        let payload_bytes = serde_json::to_string(
            &serde_json::to_value(&payload)
                .map_err(|_| ProviderError::Provider("receipt encode failed".to_string()))?,
        )
        .map_err(|_| ProviderError::Provider("receipt encode failed".to_string()))?;
        let (signature, signer_did) = crate::crypto::domain_separated_sign(
            &self.signing_key,
            "elastos.content.availability.receipt.v1",
            payload_bytes.as_bytes(),
        );
        Ok(ok_provider_response(json!({
            "receipt": crate::content::SignedAvailabilityReceipt {
                payload,
                signature,
                signer_did,
            },
        })))
    }

    async fn fetch(&self, request: &Value) -> Result<Value, ProviderError> {
        let path = request
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing fetch path".to_string()))?;
        let mut bytes = if path == crate::content::CONTENT_OBJECT_MANIFEST_PATH
            && self.config.mutate_manifest_extra_file
        {
            let mut manifest = self
                .manifest
                .lock()
                .await
                .clone()
                .ok_or_else(|| ProviderError::Provider("missing manifest".to_string()))?;
            manifest.files.push(manifest.files[0].clone());
            serde_json::to_vec(&manifest)
                .map_err(|_| ProviderError::Provider("manifest encode failed".to_string()))?
        } else {
            self.files
                .lock()
                .await
                .get(path)
                .cloned()
                .ok_or_else(|| ProviderError::NotFound("content object file".to_string()))?
        };
        if self.config.mutate_fetch_path.as_deref() == Some(path) {
            let first = bytes
                .first_mut()
                .ok_or_else(|| ProviderError::Provider("empty fetch mutation".to_string()))?;
            *first ^= 0x01;
        }
        Ok(ok_provider_response(json!({
            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
        })))
    }

    async fn seed_published_protected_content(
        &self,
        directory: &Path,
        object_identity: &str,
        publisher_did: &str,
    ) -> Result<(), ProviderError> {
        let files = super::protected_content_directory_files(directory)
            .map_err(|error| ProviderError::Provider(error.to_string()))?
            .into_iter()
            .map(|path| {
                let bytes = fs::read(directory.join(&path))
                    .map_err(|error| ProviderError::Provider(error.to_string()))?;
                Ok(json!({
                    "path": path,
                    "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                }))
            })
            .collect::<Result<Vec<_>, ProviderError>>()?;
        self.publish(&json!({
            "op": "publish",
            "object_kind": "protected-content",
            "object_did": object_identity,
            "publisher_did": publisher_did,
            "files": files,
        }))
        .await?;
        Ok(())
    }

    async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl Provider for ContentAvailabilityTestProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "content availability test provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["content"]
    }

    fn name(&self) -> &'static str {
        "content-availability-test-provider"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        match request.get("op").and_then(Value::as_str) {
            Some("publish") => self.publish(request).await,
            Some("ensure") => Ok(ok_provider_response(json!({
                "availability": { "status": self.config.status.clone() },
            }))),
            Some("status") => self.status().await,
            Some("fetch") => self.fetch(request).await,
            _ => Err(ProviderError::Provider(
                "unsupported content operation".to_string(),
            )),
        }
    }
}

const NOW: u64 = 2_000_000_000;
const MEDIA_MIME_TYPE_V1: &str = "video/mp4";
const MEDIA_CODECS_V1: &str = "avc1.640028,mp4a.40.2";
const PQ_HYBRID_AEAD_NONCE_BYTES: usize = 12;
const PQ_HYBRID_WRAPPED_SHARE_BYTES: usize = 48;

impl RecordingProvider {
    fn new(name: &'static str, response: Value) -> Arc<Self> {
        Arc::new(Self {
            name,
            requests: Mutex::new(Vec::new()),
            response,
        })
    }

    async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

impl SequencedProvider {
    fn new(name: &'static str, responses: Vec<Result<Value, ProviderError>>) -> Arc<Self> {
        Arc::new(Self {
            name,
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from(responses)),
        })
    }

    async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

impl PrepareOnlyCleanupDecryptProvider {
    fn new() -> Arc<Self> {
        Self::with_expected_issuer_seed(0x21)
    }

    fn with_expected_issuer_seed(seed: u8) -> Arc<Self> {
        Arc::new(Self {
            expected_issuer_seed: seed,
            requests: Mutex::new(Vec::new()),
        })
    }

    async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

impl ProcessChainEvidenceProvider {
    fn new(expected_request: RightsProviderRequestV1, has_access: bool) -> Arc<Self> {
        Arc::new(Self {
            expected_request,
            requests: Mutex::new(Vec::new()),
            has_access,
        })
    }

    async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl Provider for PrepareOnlyCleanupDecryptProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "prepare-only cleanup decrypt provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["decrypt"]
    }

    fn name(&self) -> &'static str {
        "prepare-only-cleanup-decrypt-provider"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        let mut inner_request = request.clone();
        inner_request
            .as_object_mut()
            .ok_or_else(|| ProviderError::Provider("invalid decrypt request".to_string()))?
            .remove("_runtime_invocation");
        let validated = ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &serde_json::to_vec(&inner_request)
                .map_err(|_| ProviderError::Provider("invalid decrypt request".to_string()))?,
            derived_device_runtime_issuer(self.expected_issuer_seed),
            crate::auth::now_ts(),
        )
        .map_err(|_| ProviderError::Provider("invalid decrypt request".to_string()))?;
        match request.get("op").and_then(Value::as_str) {
            Some("prepare_recipient") => Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_prepared_recipient(
                        validated.audit_request_id(),
                        opaque_handle(0x71),
                        recipient_public_key(0x30),
                        &recipient_identity(0x30),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Some("close_viewer_session") => Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_viewer_session_already_absent(
                        validated.audit_request_id(),
                        *validated.viewer_session_handle().map_err(|_| {
                            ProviderError::Provider("missing viewer handle".to_string())
                        })?,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Some("cancel_prepared_recipient") => Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_cancelled_prepared_recipient(
                        validated.audit_request_id(),
                        *validated.prepared_recipient_handle().map_err(|_| {
                            ProviderError::Provider("missing prepared handle".to_string())
                        })?,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            _ => Err(ProviderError::Provider(
                "unsupported decrypt operation".to_string(),
            )),
        }
    }
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new([byte; 32])
}

fn encrypted_content(seed: u8) -> EncryptedContentIdentityV1 {
    EncryptedContentIdentityV1::new(digest(seed), 4096).unwrap()
}

fn content_access_id(seed: u8) -> ContentAccessIdV1 {
    ContentAccessIdV1::new([seed; 16]).unwrap()
}

fn wallet(seed: u8) -> WalletAddress {
    let key = WalletSigningKey::from_slice(&[seed; 32]).unwrap();
    let encoded = key.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    WalletAddress::new(digest[12..].try_into().unwrap())
}

fn runtime_operation_issuer_for_seed(seed: u8) -> RuntimeOperationIssuerKeyV1 {
    RuntimeOperationIssuerKeyV1::new(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

fn sign_runtime_statement_for_seed_0x21(message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(&[0x21; 32]).sign(message).to_bytes()
}

#[cfg(unix)]
fn required_test_binary_path(env_name: &str) -> PathBuf {
    let path = PathBuf::from(
        env::var_os(env_name).unwrap_or_else(|| panic!("missing test binary env: {env_name}")),
    );
    let metadata = fs::metadata(&path)
        .unwrap_or_else(|error| panic!("invalid test binary path {}: {error}", path.display()));
    assert!(
        metadata.is_file(),
        "test binary is not a file: {}",
        path.display()
    );
    assert!(
        metadata.permissions().mode() & 0o111 != 0,
        "test binary is not executable: {}",
        path.display()
    );
    path
}

#[cfg(unix)]
fn runtime_issuer_hex(seed: u8) -> String {
    format!(
        "0x{}",
        hex::encode(runtime_operation_issuer_for_seed(seed).as_bytes())
    )
}

fn wallet_address_hex(wallet: WalletAddress) -> String {
    format!("0x{}", hex::encode(wallet.as_bytes()))
}

#[cfg(unix)]
fn collect_file_bytes(root: &Path, out: &mut Vec<Vec<u8>>) {
    let mut entries = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_file_bytes(&path, out);
        } else if path.is_file() {
            out.push(fs::read(path).unwrap());
        }
    }
}

#[cfg(unix)]
fn any_file_contains(root: &Path, needle: &[u8]) -> bool {
    if !root.exists() {
        return false;
    }
    let mut files = Vec::new();
    collect_file_bytes(root, &mut files);
    files.into_iter().any(|bytes| {
        !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
    })
}

#[cfg(unix)]
async fn invoke_typed_protect_provider(
    registry: &ProviderRegistry,
    op: &str,
    request: &ProtectProviderRequestV1,
) -> ProtectProviderResponseV1 {
    let data = invoke_json_provider(
        registry,
        "protect",
        op,
        serde_json::to_value(request).unwrap(),
    )
    .await
    .unwrap();
    ProtectProviderResponseV1::from_json_slice(&serde_json::to_vec(&data).unwrap()).unwrap()
}

#[cfg(unix)]
fn provision_custody_node_public_receipt(
    binary: &Path,
    state_root: &Path,
    runtime_issuer_seed: u8,
) -> ProvisionedCustodyProviderPublicKeys {
    let output = Command::new(binary)
        .args([
            "provision",
            "--base-path",
            state_root.to_str().unwrap(),
            "--trusted-runtime-issuer",
            &runtime_issuer_hex(runtime_issuer_seed),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    parse_and_verify_provisioning_output(
        &response,
        runtime_operation_issuer_for_seed(runtime_issuer_seed),
    )
    .unwrap()
}

fn node_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn node_public_key(seed: u8) -> NodePublicKey {
    NodePublicKey::new(node_signing_key(seed).verifying_key().to_bytes()).unwrap()
}

fn xwing_public_key_bytes(
    seed: u8,
) -> [u8; elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

fn recipient_public_key(seed: u8) -> RecipientPublicKeyBytesV1 {
    RecipientPublicKeyBytesV1::new(xwing_public_key_bytes(seed.max(9))).unwrap()
}

fn recipient_identity(seed: u8) -> RecipientKeyIdentityV1 {
    recipient_public_key(seed)
        .key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
        .unwrap()
}

fn node_custody_public_key(seed: u8) -> NodeCustodyPublicKeyV1 {
    NodeCustodyPublicKeyV1::new(xwing_public_key_bytes(seed)).unwrap()
}

fn make_box(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let size = (8 + content.len()) as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(box_type);
    out.extend_from_slice(content);
    out
}

fn make_fullbox(box_type: &[u8; 4], flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut content = vec![0u8];
    content.extend_from_slice(&flags.to_be_bytes()[1..]);
    content.extend_from_slice(payload);
    make_box(box_type, &content)
}

fn make_sinf(original_fourcc: &[u8; 4]) -> Vec<u8> {
    let frma = make_box(b"frma", original_fourcc);
    let mut schm_payload = Vec::new();
    schm_payload.extend_from_slice(b"cenc");
    schm_payload.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    let schm = make_fullbox(b"schm", 0, &schm_payload);
    let mut tenc_payload = vec![0, 0, 1, 8];
    tenc_payload.extend_from_slice(&[0x44; 16]);
    let tenc = make_fullbox(b"tenc", 0, &tenc_payload);
    let schi = make_box(b"schi", &tenc);
    let mut sinf_content = Vec::new();
    sinf_content.extend_from_slice(&frma);
    sinf_content.extend_from_slice(&schm);
    sinf_content.extend_from_slice(&schi);
    make_box(b"sinf", &sinf_content)
}

fn make_track(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
    let mut tkhd_payload = vec![0u8; 12];
    tkhd_payload[8..12].copy_from_slice(&track_id.to_be_bytes());
    let tkhd = make_fullbox(b"tkhd", 0, &tkhd_payload);
    let mut hdlr_payload = vec![0u8; 4];
    hdlr_payload.extend_from_slice(handler_type);
    let hdlr = make_fullbox(b"hdlr", 0, &hdlr_payload);
    let (entry_type, orig_type, fixed) = match handler_type {
        b"vide" => (b"encv", b"avc1", 78usize),
        b"soun" => (b"enca", b"mp4a", 28usize),
        _ => panic!("unsupported handler"),
    };
    let mut entry_content = vec![0u8; fixed];
    entry_content.extend_from_slice(&make_sinf(orig_type));
    let entry = make_box(entry_type, &entry_content);
    let mut stsd_payload = vec![0u8; 4];
    stsd_payload.extend_from_slice(&1u32.to_be_bytes());
    stsd_payload.extend_from_slice(&entry);
    let stsd = make_box(b"stsd", &stsd_payload);
    let stbl = make_box(b"stbl", &stsd);
    let minf = make_box(b"minf", &stbl);
    let mut mdia_content = Vec::new();
    mdia_content.extend_from_slice(&hdlr);
    mdia_content.extend_from_slice(&minf);
    let mdia = make_box(b"mdia", &mdia_content);
    let mut trak_content = Vec::new();
    trak_content.extend_from_slice(&tkhd);
    trak_content.extend_from_slice(&mdia);
    make_box(b"trak", &trak_content)
}

fn make_clear_track(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
    let mut tkhd_payload = vec![0u8; 12];
    tkhd_payload[8..12].copy_from_slice(&track_id.to_be_bytes());
    let tkhd = make_fullbox(b"tkhd", 0, &tkhd_payload);
    let mut hdlr_payload = vec![0u8; 4];
    hdlr_payload.extend_from_slice(handler_type);
    let hdlr = make_fullbox(b"hdlr", 0, &hdlr_payload);
    let (entry_type, fixed) = match handler_type {
        b"vide" => (b"avc1", 78usize),
        b"soun" => (b"mp4a", 28usize),
        _ => panic!("unsupported handler"),
    };
    let entry = make_box(entry_type, &vec![0u8; fixed]);
    let mut stsd_payload = vec![0u8; 4];
    stsd_payload.extend_from_slice(&1u32.to_be_bytes());
    stsd_payload.extend_from_slice(&entry);
    let stsd = make_box(b"stsd", &stsd_payload);
    let stbl = make_box(b"stbl", &stsd);
    let minf = make_box(b"minf", &stbl);
    let mut mdia_content = Vec::new();
    mdia_content.extend_from_slice(&hdlr);
    mdia_content.extend_from_slice(&minf);
    let mdia = make_box(b"mdia", &mdia_content);
    let mut trak_content = Vec::new();
    trak_content.extend_from_slice(&tkhd);
    trak_content.extend_from_slice(&mdia);
    make_box(b"trak", &trak_content)
}

fn make_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut tfhd_payload = Vec::new();
    tfhd_payload.extend_from_slice(&track_id.to_be_bytes());
    tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
    tfhd_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tfhd_payload.extend_from_slice(&0u32.to_be_bytes());
    let tfhd = make_fullbox(b"tfhd", 0x020038, &tfhd_payload);
    let tfdt = make_fullbox(b"tfdt", 0, &1u32.to_be_bytes());
    let mut trun_payload = Vec::new();
    trun_payload.extend_from_slice(&1u32.to_be_bytes());
    trun_payload.extend_from_slice(&0i32.to_be_bytes());
    trun_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    let trun = make_fullbox(b"trun", 0x000201, &trun_payload);
    let mut senc_payload = Vec::new();
    senc_payload.extend_from_slice(&1u32.to_be_bytes());
    senc_payload.extend_from_slice(&(0x10u64 + u64::from(track_id)).to_be_bytes());
    let senc = make_fullbox(b"senc", 0, &senc_payload);
    let mut traf_content = Vec::new();
    traf_content.extend_from_slice(&tfhd);
    traf_content.extend_from_slice(&tfdt);
    traf_content.extend_from_slice(&trun);
    traf_content.extend_from_slice(&senc);
    let traf = make_box(b"traf", &traf_content);
    let mfhd = make_fullbox(b"mfhd", 0, &1u32.to_be_bytes());
    let mut moof_content = Vec::new();
    moof_content.extend_from_slice(&mfhd);
    moof_content.extend_from_slice(&traf);
    let mut moof = make_box(b"moof", &moof_content);
    let data_offset = (moof.len() + 8) as i32;
    let trun_offset = moof
        .windows(4)
        .position(|window| window == b"trun")
        .expect("trun box present")
        - 4;
    let trun_data_offset_at = trun_offset + 16;
    moof[trun_data_offset_at..trun_data_offset_at + 4].copy_from_slice(&data_offset.to_be_bytes());
    let mdat = make_box(b"mdat", payload);
    let mut out = moof;
    out.extend_from_slice(&mdat);
    out
}

fn make_clear_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut tfhd_payload = Vec::new();
    tfhd_payload.extend_from_slice(&track_id.to_be_bytes());
    tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
    tfhd_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tfhd_payload.extend_from_slice(&0u32.to_be_bytes());
    let tfhd = make_fullbox(b"tfhd", 0x020038, &tfhd_payload);
    let tfdt = make_fullbox(b"tfdt", 0, &1u32.to_be_bytes());
    let mut trun_payload = Vec::new();
    trun_payload.extend_from_slice(&1u32.to_be_bytes());
    trun_payload.extend_from_slice(&0i32.to_be_bytes());
    trun_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    let trun = make_fullbox(b"trun", 0x000201, &trun_payload);
    let mut traf_content = Vec::new();
    traf_content.extend_from_slice(&tfhd);
    traf_content.extend_from_slice(&tfdt);
    traf_content.extend_from_slice(&trun);
    let traf = make_box(b"traf", &traf_content);
    let mfhd = make_fullbox(b"mfhd", 0, &1u32.to_be_bytes());
    let mut moof_content = Vec::new();
    moof_content.extend_from_slice(&mfhd);
    moof_content.extend_from_slice(&traf);
    let mut moof = make_box(b"moof", &moof_content);
    let data_offset = (moof.len() + 8) as i32;
    let trun_offset = moof
        .windows(4)
        .position(|window| window == b"trun")
        .expect("trun box present")
        - 4;
    let trun_data_offset_at = trun_offset + 16;
    moof[trun_data_offset_at..trun_data_offset_at + 4].copy_from_slice(&data_offset.to_be_bytes());
    let mdat = make_box(b"mdat", payload);
    let mut out = moof;
    out.extend_from_slice(&mdat);
    out
}

pub(crate) fn media_components(seed: u8) -> (Vec<u8>, Vec<Vec<u8>>) {
    let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
    let trak_video = make_track(1, b"vide");
    let trak_audio = make_track(2, b"soun");
    let trex_video = make_fullbox(
        b"trex",
        0,
        &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let trex_audio = make_fullbox(
        b"trex",
        0,
        &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let mut mvex_content = Vec::new();
    mvex_content.extend_from_slice(&trex_video);
    mvex_content.extend_from_slice(&trex_audio);
    let mvex = make_box(b"mvex", &mvex_content);
    let mvhd = make_box(b"mvhd", &[0u8; 4]);
    let mut moov_content = Vec::new();
    moov_content.extend_from_slice(&mvhd);
    moov_content.extend_from_slice(&trak_video);
    moov_content.extend_from_slice(&trak_audio);
    moov_content.extend_from_slice(&mvex);
    let moov = make_box(b"moov", &moov_content);
    let encrypted_segments = [0usize, 1]
        .into_iter()
        .map(|index| {
            let track_id = if index % 2 == 0 { 1 } else { 2 };
            let payload = vec![
                seed,
                track_id as u8,
                (index & 0xff) as u8,
                ((index >> 8) & 0xff) as u8,
                b's',
                b'e',
                b'g',
                b'x',
            ];
            make_segment(track_id, &payload)
        })
        .collect();
    ([ftyp, moov].concat(), encrypted_segments)
}

fn clear_media_components(seed: u8) -> (Vec<u8>, Vec<Vec<u8>>) {
    let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
    let trak_video = make_clear_track(1, b"vide");
    let trak_audio = make_clear_track(2, b"soun");
    let trex_video = make_fullbox(
        b"trex",
        0,
        &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let trex_audio = make_fullbox(
        b"trex",
        0,
        &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let mut mvex_content = Vec::new();
    mvex_content.extend_from_slice(&trex_video);
    mvex_content.extend_from_slice(&trex_audio);
    let mvex = make_box(b"mvex", &mvex_content);
    let mvhd = make_box(b"mvhd", &[0u8; 4]);
    let mut moov_content = Vec::new();
    moov_content.extend_from_slice(&mvhd);
    moov_content.extend_from_slice(&trak_video);
    moov_content.extend_from_slice(&trak_audio);
    moov_content.extend_from_slice(&mvex);
    let moov = make_box(b"moov", &moov_content);
    let clear_segments = [0usize, 1]
        .into_iter()
        .map(|index| {
            let track_id = if index % 2 == 0 { 1 } else { 2 };
            let payload = vec![
                seed,
                track_id as u8,
                (index & 0xff) as u8,
                ((index >> 8) & 0xff) as u8,
                b's',
                b'e',
                b'g',
                b'x',
            ];
            make_clear_segment(track_id, &payload)
        })
        .collect();
    ([ftyp, moov].concat(), clear_segments)
}

fn media_identity(seed: u8) -> CencFmp4MediaIdentityV1 {
    let (init_segment, encrypted_segments) = media_components(seed);
    CencFmp4MediaIdentityV1::new_from_bytes(
        &init_segment,
        &encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
    )
    .unwrap()
}

fn protected_content_directory_from_parts(
    init: &[u8],
    segments: &[Vec<u8>],
    media: &CencFmp4MediaIdentityV1,
) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let protected_root = directory.path().join("protected-content/v1/segments");
    fs::create_dir_all(&protected_root).unwrap();
    fs::write(
        directory.path().join("protected-content/v1/identity.bin"),
        media.canonical_bytes().unwrap(),
    )
    .unwrap();
    fs::write(directory.path().join("protected-content/v1/init.mp4"), init).unwrap();
    for (index, segment) in segments.iter().enumerate() {
        fs::write(protected_root.join(format!("{index:08}.m4s")), segment).unwrap();
    }
    directory
}

fn availability_requirement(
    expected_provider_did: impl Into<String>,
) -> RuntimeContentAvailabilityRequirement {
    RuntimeContentAvailabilityRequirement::new(
        expected_provider_did,
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content",
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
        "protected-content-replication/v1",
        super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        60,
        5,
    )
    .unwrap()
}

fn protected_content_directory(seed: u8) -> (tempfile::TempDir, CencFmp4MediaIdentityV1) {
    let (init, segments) = media_components(seed);
    let media = CencFmp4MediaIdentityV1::new_from_bytes(
        &init,
        &segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
    )
    .unwrap();
    (
        protected_content_directory_from_parts(&init, &segments, &media),
        media,
    )
}

/// What a v1 mint used to do after staging, kept only to publish v1 fixtures:
/// publish the directory and verify what was published with the production v1
/// read-side checks (`verify_protected_content_manifest_and_files` and
/// `verify_protected_content_receipt`). New mints write v2; v1 is still read.
async fn publish_and_verify_v1_protected_content_for_test(
    registry: &ProviderRegistry,
    protected_content_dir: &Path,
    media_identity: &CencFmp4MediaIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeVerifiedContentAvailability> {
    super::validate_protected_content_availability_requirement(requirement)?;
    let publish_requirements = crate::content::ContentPublishRequirements::new(
        requirement.minimum_replicas(),
        super::protected_content_live_proof_required(requirement.minimum_replicas()),
    )?
    .with_availability_policy(requirement.policy())?;
    let content_cid = crate::content::publish_directory_via_provider_with_kind_and_requirements(
        registry,
        protected_content_dir,
        super::PROTECTED_CONTENT_OBJECT_KIND,
        Some(requirement.expected_object_identity()),
        Some(requirement.expected_publisher_did()),
        publish_requirements,
    )
    .await?;
    let receipt = super::fetch_content_availability_receipt(registry, &content_cid).await?;
    let manifest = crate::content::fetch_content_object_manifest(registry, &content_cid).await?;
    super::verify_protected_content_manifest_and_files(
        registry,
        &content_cid,
        &manifest,
        media_identity,
    )
    .await?;
    super::verify_protected_content_receipt(
        &content_cid,
        &manifest,
        &receipt,
        media_identity,
        requirement,
        now_unix_seconds(),
        super::RuntimeManifestPublisherBinding::Exact,
    )
}

async fn publish_protected_content_for_test(
    config: ContentAvailabilityTestConfig,
    expected_provider_did: Option<String>,
    mutate_directory: Option<fn(&Path)>,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeVerifiedContentAvailability> {
    let (directory, media) = protected_content_directory(0x41);
    if let Some(mutate_directory) = mutate_directory {
        mutate_directory(directory.path());
    }
    let provider = ContentAvailabilityTestProvider::new(0x61, config);
    let expected_provider_did = expected_provider_did.unwrap_or_else(|| provider.signer_did());
    let requirement = availability_requirement(expected_provider_did);
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("content", provider)
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
}

struct RuntimeCustodyPrebuyAvailabilityHarness {
    _temp: tempfile::TempDir,
    data_dir: PathBuf,
    registry: Arc<ProviderRegistry>,
    content_provider: Arc<ContentAvailabilityTestProvider>,
    mint_id: Digest32,
}

/// Persists a creator's listing for `mint_id` whose package names these
/// three CIDs and which was published at `elastos://<listing_cid>`.
#[cfg(unix)]
pub(crate) fn persist_creator_listing_for_test(
    data_dir: &Path,
    publisher_principal_id: &str,
    mint_id: Digest32,
    content_cid: &str,
    metadata_cid: &str,
    listing_cid: &str,
) {
    owner_only_dir(data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    let mut listing =
        runtime_custody_listing_record_for_test(mint_id, publisher_principal_id, "Film", NOW);
    listing.package.content_cid = content_cid.to_string();
    listing.package.metadata_cid = metadata_cid.to_string();
    listing.package.token_uri = format!("ipfs://{metadata_cid}");
    listing.origin = super::RuntimeCustodyListingOrigin::LocalCreator {
        principal_id: publisher_principal_id.to_string(),
        listing_uri: format!("elastos://{listing_cid}"),
        package_sha256: hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&listing.package).unwrap(),
        )),
    };
    super::persist_runtime_custody_listing(data_dir, &listing).unwrap();
}

fn runtime_custody_listing_record_for_test(
    mint_id: Digest32,
    publisher_principal_id: &str,
    display_name: &str,
    published_at: u64,
) -> super::RuntimeCustodyListingRecord {
    let draft = mint_draft_for_composition_journal_test();
    let publisher_profile_did = derived_device_key_for_seed(0x66).1;
    let content_id = super::runtime_protected_content_id(draft.encrypted_content()).unwrap();
    let package = super::RuntimePortableListingPackage {
        schema: super::RUNTIME_PORTABLE_LISTING_SCHEMA_V1.to_string(),
        mint_id: hex::encode(mint_id.as_bytes()),
        content_id,
        content_access_id: format!("0x{}", hex::encode(draft.content_access_id().as_bytes())),
        content_cid: ContentAvailabilityTestProvider::CID.to_string(),
        metadata_cid: ContentAvailabilityTestProvider::CID.to_string(),
        token_uri: format!(
            "ipfs://{}/metadata.json",
            ContentAvailabilityTestProvider::CID
        ),
        publisher_profile_did,
        display_name: display_name.to_string(),
        media_identity_base64: Some(
            base64::engine::general_purpose::STANDARD
                .encode(draft.media_identity().unwrap().canonical_bytes().unwrap()),
        ),
        content_identity_base64: None,
        key_envelope_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.key_envelope().canonical_bytes().unwrap()),
        rights_policy_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.policy().canonical_bytes().unwrap()),
        content_key_commitment_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.content_key_commitment().as_bytes()),
        quantity: "0x2".to_string(),
        seller_address: "0x0000000000000000000000000000000000000011".to_string(),
        chain_namespace: "eip155:8453".to_string(),
        network: "base-mainnet".to_string(),
        ledger: "0x0000000000000000000000000000000000000022".to_string(),
        token_id: "0x1".to_string(),
        operative: "0x0000000000000000000000000000000000000033".to_string(),
        price: "0x5".to_string(),
        pay_token: "0x0000000000000000000000000000000000000044".to_string(),
        payment_processor: Some("0x0000000000000000000000000000000000000055".to_string()),
        mint_transaction_hash: Some(format!("0x{}", hex::encode([0x68; 32]))),
        published_at: Some(published_at),
        pool_mint_share_b64: None,
    };
    super::RuntimeCustodyListingRecord {
        schema: super::RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin: super::RuntimeCustodyListingOrigin::LocalCreator {
            principal_id: publisher_principal_id.to_string(),
            listing_uri: format!("elastos://{}", ContentAvailabilityTestProvider::CID),
            package_sha256: hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(&package).unwrap(),
            )),
        },
        package,
        availability: super::RuntimeCustodyListingAvailabilitySummary {
            kind: "receipt".to_string(),
            checked_at: NOW,
            observed_replicas: 3,
            receipt_digest: hex::encode([0x67; 32]),
        },
    }
}

#[cfg(unix)]
pub(crate) fn make_runtime_custody_listing_imported_without_creator_mint(
    data_dir: &Path,
    mint_id: Digest32,
) {
    let mut listing = super::load_runtime_custody_listing(data_dir, mint_id)
        .unwrap()
        .unwrap();
    let (listing_uri, package_sha256) = match &listing.origin {
        super::RuntimeCustodyListingOrigin::LocalCreator {
            listing_uri,
            package_sha256,
            ..
        }
        | super::RuntimeCustodyListingOrigin::Imported {
            listing_uri,
            package_sha256,
        } => (listing_uri.clone(), package_sha256.clone()),
        super::RuntimeCustodyListingOrigin::Asset { .. }
        | super::RuntimeCustodyListingOrigin::Granted { .. } => {
            panic!("an adopted listing has no published package to import")
        }
    };
    listing.origin = super::RuntimeCustodyListingOrigin::Imported {
        listing_uri,
        package_sha256,
    };
    super::persist_runtime_custody_listing(data_dir, &listing).unwrap();
    fs::remove_dir_all(data_dir.join(super::RUNTIME_MINT_JOURNAL_ROOT)).unwrap();
    assert!(!data_dir.join(super::RUNTIME_MINT_JOURNAL_ROOT).exists());
}

async fn runtime_custody_prebuy_availability_harness(
    provider_seed: u8,
    provider_config: ContentAvailabilityTestConfig,
) -> RuntimeCustodyPrebuyAvailabilityHarness {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    write_device_key(&data_dir, 0x61);
    write_library_publish_test_composition(&data_dir);

    let mint_draft = mint_draft_for_composition_journal_test();
    let fixture_now = crate::auth::now_ts();
    let mint_journal = runtime_mint_journal(&data_dir);
    mint_journal.persist_bound(&mint_draft).unwrap();
    for (index, node) in mint_draft.nodes().iter().enumerate() {
        let seed = u8::try_from(index + 1).unwrap();
        mint_journal
            .mark_node_effect_started(mint_draft.mint_id(), node.node_public_key())
            .unwrap();
        mint_journal
            .mark_node_receipt(
                mint_draft.mint_id(),
                RuntimeMintNodeReceipt::new(
                    node.node_public_key(),
                    RuntimeCustodyProvisioningIdV1::new(digest(0x80 + seed)).unwrap(),
                    CustodyNodeProvisioningRecordIdentityV1::new(digest(0xa0 + seed), 128).unwrap(),
                    node.owner_state_root(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let custody_provisioned = mint_journal
        .mark_custody_provisioned(mint_draft.mint_id())
        .unwrap();
    assert_eq!(
        custody_provisioned.custody_terminal(),
        Some(elastos_protected_content_runtime::RuntimeCustodyTerminalKind::CustodyProvisioned)
    );

    let expected_provider_did =
        ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted())
            .signer_did();
    let requirement = RuntimeContentAvailabilityRequirement::new(
        expected_provider_did,
        super::runtime_protected_content_id(mint_draft.encrypted_content()).unwrap(),
        derived_device_key_for_seed(0x66).1,
        super::PROTECTED_CONTENT_REPLICATION_POLICY,
        super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .unwrap();
    let evidence = elastos_protected_content_runtime::RuntimeVerifiedContentAvailability::new(
        ContentAvailabilityTestProvider::CID,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        &requirement,
        3,
        fixture_now.saturating_sub(1),
        digest(0x71),
        mint_draft.encrypted_content().clone(),
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media(
            mint_draft.media_identity().unwrap(),
        ),
    )
    .unwrap();
    let available = mint_journal
        .mark_content_available(mint_draft.mint_id(), &requirement, evidence)
        .unwrap();
    assert_eq!(available.draft().mint_id(), mint_draft.mint_id());
    assert!(available.content_availability().is_some());

    let listing = runtime_custody_listing_record_for_test(
        mint_draft.mint_id(),
        "person:local:creator",
        "protected-video.mp4",
        fixture_now.saturating_sub(2),
    );
    super::persist_runtime_custody_listing(&data_dir, &listing).unwrap();

    let (init_segment, encrypted_segments) = media_components(0x41);
    let media_identity = CencFmp4MediaIdentityV1::new_from_bytes(
        &init_segment,
        &encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
    )
    .unwrap();
    let protected_directory =
        protected_content_directory_from_parts(&init_segment, &encrypted_segments, &media_identity);
    let content_provider = ContentAvailabilityTestProvider::new(provider_seed, provider_config);
    content_provider
        .seed_published_protected_content(
            protected_directory.path(),
            requirement.expected_object_identity(),
            requirement.expected_publisher_did(),
        )
        .await
        .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("content", content_provider.clone())
        .await
        .unwrap();

    RuntimeCustodyPrebuyAvailabilityHarness {
        _temp: temp,
        data_dir,
        registry,
        content_provider,
        mint_id: mint_draft.mint_id(),
    }
}

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
        super::list_runtime_custody_listings(&harness.data_dir, "person:local:creator").unwrap();
    assert_eq!(
        creator_view["schema"],
        super::RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1
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
            "codecs",
            "content_kind",
            "display_name",
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
        "schema": super::RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1,
        "status": "last_verified_receipt",
        "checked_at": NOW,
        "required_replicas": super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        "observed_replicas": 3,
        "receipt_digest": hex::encode([0x67; 32]),
        "recheck_before_buy": true,
        "recheck_before_open": true,
    });
    assert_eq!(creator_listing["availability"], expected_availability);
    assert_eq!(creator_listing["access_state"], "creator");

    let buyer_view =
        super::list_runtime_custody_listings(&harness.data_dir, buyer_principal_id).unwrap();
    assert_eq!(buyer_view["listings"][0]["access_state"], "purchased");
    assert_eq!(
        buyer_view["listings"][0]["availability"],
        expected_availability
    );

    let other_view =
        super::list_runtime_custody_listings(&harness.data_dir, "person:local:other").unwrap();
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
    let listings_root = data_dir.join(super::RUNTIME_LISTING_ROOT);
    owner_only_dir(&listings_root);

    for index in (0..(super::MAX_RUNTIME_CUSTODY_LISTINGS + 3)).rev() {
        let mint_id = Digest32::new([u8::try_from(index + 1).unwrap(); 32]);
        let path = super::runtime_listing_path(&data_dir, mint_id);
        write_owner_only_bytes(&path, b"{}").unwrap();
    }

    let (first_paths, first_truncated) =
        super::select_runtime_custody_listing_paths(&listings_root).unwrap();
    let (second_paths, second_truncated) =
        super::select_runtime_custody_listing_paths(&listings_root).unwrap();
    assert!(first_truncated);
    assert!(second_truncated);
    assert_eq!(first_paths, second_paths);
    assert_eq!(first_paths.len(), super::MAX_RUNTIME_CUSTODY_LISTINGS);
    let selected = first_paths
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let expected = (0..super::MAX_RUNTIME_CUSTODY_LISTINGS)
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
        &super::runtime_listing_path(&data_dir, mint_id),
        &serde_json::to_vec(&invalid).unwrap(),
    )
    .unwrap();

    let error = super::list_runtime_custody_listings(&data_dir, "person:local:creator")
        .expect_err("expected malformed record rejection");
    assert_eq!(error.to_string(), "Runtime custody listing is invalid");
}

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
    assert_eq!(
        evidence.required_replicas(),
        super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET
    );
    assert_eq!(evidence.observed_replicas(), 3);
    let debug = format!("{evidence:?}");
    assert!(!debug.contains("init.mp4"));
    assert!(!debug.contains("segments/"));
}

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
    let listing = super::load_runtime_custody_listing(&harness.data_dir, harness.mint_id)
        .unwrap()
        .unwrap();
    let (_, verified) = super::verify_fresh_runtime_custody_availability(
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
        super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR
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
        super::PROTECTED_CONTENT_REPLICATION_POLICY
    );
    assert_eq!(
        ensure["availability_requirements"]["min_replicas"],
        super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR
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
            checked_at: now - super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS - 1,
            ..ContentAvailabilityTestConfig::accepted()
        },
    )
    .await;
    let listing = super::load_runtime_custody_listing(&harness.data_dir, harness.mint_id)
        .unwrap()
        .unwrap();
    assert!(super::verify_fresh_runtime_custody_availability(
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
        let listing = super::load_runtime_custody_listing(&harness.data_dir, harness.mint_id)
            .unwrap()
            .unwrap();
        assert!(super::verify_fresh_runtime_custody_availability(
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
    let listing = super::load_runtime_custody_listing(&wrong_signer.data_dir, wrong_signer.mint_id)
        .unwrap()
        .unwrap();
    assert!(super::verify_fresh_runtime_custody_availability(
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
    fs::remove_file(super::runtime_listing_path(
        &missing_listing.data_dir,
        missing_listing.mint_id,
    ))
    .unwrap();
    assert!(super::load_runtime_custody_listing(
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
    let listing = super::load_runtime_custody_listing(&wrong_mint.data_dir, wrong_mint.mint_id)
        .unwrap()
        .unwrap();
    assert!(super::verify_fresh_runtime_custody_availability(
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

fn mutate_protected_content_descriptor(directory: &Path) {
    fs::write(
        directory.join("protected-content/v1/identity.bin"),
        b"not-a-canonical-media-identity",
    )
    .unwrap();
}

fn mutate_protected_content_segment(directory: &Path) {
    let path = directory.join("protected-content/v1/segments/00000000.m4s");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 0x01;
    fs::write(path, bytes).unwrap();
}

fn remove_protected_content_descriptor(directory: &Path) {
    fs::remove_file(directory.join("protected-content/v1/identity.bin")).unwrap();
}

fn rename_protected_content_descriptor(directory: &Path) {
    fs::rename(
        directory.join("protected-content/v1/identity.bin"),
        directory.join("protected-content/v1/identity-renamed.bin"),
    )
    .unwrap();
}

fn remove_protected_content_init(directory: &Path) {
    fs::remove_file(directory.join("protected-content/v1/init.mp4")).unwrap();
}

fn rename_protected_content_init(directory: &Path) {
    fs::rename(
        directory.join("protected-content/v1/init.mp4"),
        directory.join("protected-content/v1/init-renamed.mp4"),
    )
    .unwrap();
}

fn remove_protected_content_segment(directory: &Path) {
    fs::remove_file(directory.join("protected-content/v1/segments/00000000.m4s")).unwrap();
}

fn rename_protected_content_segment(directory: &Path) {
    fs::rename(
        directory.join("protected-content/v1/segments/00000000.m4s"),
        directory.join("protected-content/v1/segments/00000000-renamed.m4s"),
    )
    .unwrap();
}

fn reorder_protected_content_segments(directory: &Path) {
    let first = directory.join("protected-content/v1/segments/00000000.m4s");
    let second = directory.join("protected-content/v1/segments/00000001.m4s");
    let first_bytes = fs::read(&first).unwrap();
    let second_bytes = fs::read(&second).unwrap();
    fs::write(first, second_bytes).unwrap();
    fs::write(second, first_bytes).unwrap();
}

fn add_protected_content_segment_index_alias(directory: &Path) {
    fs::copy(
        directory.join("protected-content/v1/segments/00000000.m4s"),
        directory.join("protected-content/v1/segments/00000000-copy.m4s"),
    )
    .unwrap();
}

fn truncate_protected_content_descriptor(directory: &Path) {
    let path = directory.join("protected-content/v1/identity.bin");
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop().unwrap();
    fs::write(path, bytes).unwrap();
}

fn mutate_protected_content_init(directory: &Path) {
    let path = directory.join("protected-content/v1/init.mp4");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 0x01;
    fs::write(path, bytes).unwrap();
}

fn truncate_protected_content_init(directory: &Path) {
    let path = directory.join("protected-content/v1/init.mp4");
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop().unwrap();
    fs::write(path, bytes).unwrap();
}

fn truncate_protected_content_segment(directory: &Path) {
    let path = directory.join("protected-content/v1/segments/00000000.m4s");
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop().unwrap();
    fs::write(path, bytes).unwrap();
}

fn add_extra_protected_content_file(directory: &Path) {
    fs::write(directory.join("protected-content/v1/extra.bin"), b"extra").unwrap();
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

fn sealed_share(seed: u8) -> PqHybridSealedShareV1 {
    let public = x_wing::EncapsulationKey::new_from_slice(&xwing_public_key_bytes(seed)).unwrap();
    let (ciphertext, _) =
        public.encapsulate_deterministic(&[seed; x_wing::ENCAPSULATION_RANDOMNESS_SIZE].into());
    let ciphertext: [u8; X_WING_DRAFT06_CIPHERTEXT_BYTES] = ciphertext.into();
    let mut envelope = Vec::with_capacity(PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES);
    envelope.extend_from_slice(&ciphertext);
    envelope.extend_from_slice(&[seed; PQ_HYBRID_AEAD_NONCE_BYTES]);
    envelope.extend_from_slice(&[seed ^ 0x5a; PQ_HYBRID_WRAPPED_SHARE_BYTES]);
    PqHybridSealedShareV1::new(envelope).unwrap()
}

fn policy_body_for(
    encrypted_content: EncryptedContentIdentityV1,
    content_access_id: ContentAccessIdV1,
    action: RightsActionV1,
) -> RightsPolicyBodyV1 {
    RightsPolicyBodyV1::new(
        encrypted_content,
        content_access_id,
        action,
        elastos_protected_content_contracts::RightsSubjectSourceV1::WalletAddress,
        11155111,
        EvmContractAddressV1::new([0x11; 20]).unwrap(),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .unwrap()
}

fn policy_body() -> RightsPolicyBodyV1 {
    policy_body_for(
        encrypted_content(0x11),
        content_access_id(0x41),
        RightsActionV1::View,
    )
}

fn signed_custody_epoch() -> SignedCustodyEpochV1 {
    signed_custody_epoch_with_first_node(node_public_key(1), node_custody_public_key(1))
}

fn signed_custody_epoch_with_first_node(
    first_node_public_key: NodePublicKey,
    first_node_custody_public_key: NodeCustodyPublicKeyV1,
) -> SignedCustodyEpochV1 {
    signed_custody_epoch_for_node_keys([
        (first_node_public_key, first_node_custody_public_key),
        (node_public_key(2), node_custody_public_key(2)),
        (node_public_key(3), node_custody_public_key(3)),
    ])
}

fn signed_custody_epoch_for_node_keys(
    nodes: [(NodePublicKey, NodeCustodyPublicKeyV1); 3],
) -> SignedCustodyEpochV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let nodes = nodes
        .into_iter()
        .enumerate()
        .map(|(index, (node_public_key, custody_public_key))| {
            elastos_protected_content_contracts::CustodyNodeIdentityV1::new(
                node_public_key,
                custody_public_key,
                ShareCoordinateV1::new(u8::try_from(index + 1).unwrap()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let statement = CustodyEpochStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        CustodyApprovedSuitesV1::new(
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        )
        .unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        nodes,
    )
    .unwrap();
    SignedCustodyEpochV1::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn signed_custody_pool_for_epoch(
    epoch: &SignedCustodyEpochV1,
    active_window: (u64, u64),
) -> SignedCustodyPoolV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let members = epoch
        .statement()
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let node_seed = u8::try_from(index + 1).unwrap();
            CustodyPoolMemberV1::new(
                node.node_public_key(),
                node.custody_public_key(),
                CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
                CustodyApprovedSuitesV1::new(
                    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                )
                .unwrap(),
                active_window,
                CustodyPoolMemberStateV1::Active,
            )
            .unwrap()
        })
        .collect();
    let statement = CustodyPoolStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        members,
    )
    .unwrap();
    SignedCustodyPoolV1::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn signed_committee_authorization_for_epoch(
    pool_identity: CustodyPoolIdentityV1,
    epoch: &SignedCustodyEpochV1,
) -> SignedCustodyCommitteeAuthorizationV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let statement = CustodyCommitteeAuthorizationStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        pool_identity,
        epoch.epoch_identity().unwrap(),
    )
    .unwrap();
    SignedCustodyCommitteeAuthorizationV1::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn validated_custody_committee_for_epoch(
    epoch: &SignedCustodyEpochV1,
    now: u64,
) -> ValidatedCustodyCommitteeV1 {
    let pool = signed_custody_pool_for_epoch(epoch, (now.saturating_sub(60), now + 3600));
    let authorization =
        signed_committee_authorization_for_epoch(pool.pool_identity().unwrap(), epoch);
    elastos_protected_content_contracts::validate_custody_epoch_against_pool_at(
        CustodyEpochIssuerKeyV1::new(
            SigningKey::from_bytes(&[0x71; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        authorization.authorization_identity().unwrap(),
        &pool,
        epoch,
        &authorization,
        now,
    )
    .unwrap()
}

fn custody_envelope_for_media(seed: u8) -> CustodyEnvelopeV1 {
    custody_envelope_for_media_with_epoch(seed, &signed_custody_epoch())
}

fn custody_envelope_for_media_with_epoch(
    seed: u8,
    epoch: &SignedCustodyEpochV1,
) -> CustodyEnvelopeV1 {
    let media = media_identity(seed);
    let manifest = CustodyEnvelopeManifestV1::new(
        media.encrypted_content().clone(),
        CustodyPoolIdentityV1::new(digest(seed ^ 0x34), 512).unwrap(),
        epoch.epoch_identity().unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(seed ^ 0x35), 512).unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        digest(seed ^ 0x33),
        epoch.statement().nodes().to_vec(),
    )
    .unwrap();
    let shares = [seed ^ 0x50, seed ^ 0x51, seed ^ 0x52]
        .into_iter()
        .map(sealed_share)
        .collect();
    CustodyEnvelopeV1::new(manifest, shares).unwrap()
}

fn provisioned_custody_envelope_for_media_with_epoch(
    seed: u8,
    epoch: &SignedCustodyEpochV1,
    now: u64,
) -> CustodyEnvelopeV1 {
    let media = media_identity(seed);
    let content_key =
        elastos_protected_content_custody::ContentEncryptionKeyV1::generate().unwrap();
    let committee = validated_custody_committee_for_epoch(epoch, now);
    provision_custody_envelope(media.encrypted_content().clone(), &content_key, &committee).unwrap()
}

fn binding_for_envelope(
    envelope: &CustodyEnvelopeV1,
) -> elastos_protected_content_contracts::ProtectedContentBindingV1 {
    let policy = policy_body();
    elastos_protected_content_contracts::ProtectedContentBindingV1::new(
        envelope.manifest().encrypted_content().clone(),
        envelope.key_envelope_identity().unwrap(),
        policy.policy_identity().unwrap(),
        elastos_protected_content_contracts::ProfileIdentityV1::from_public_key_bytes(
            SigningKey::from_bytes(&[0x26; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        wallet(7),
        RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
    )
    .unwrap()
}

#[cfg(unix)]
fn store_profile_signing_passkey(
    data_dir: &Path,
    principal_id: &str,
    credential_id: &str,
) -> String {
    let now = crate::auth::now_ts();
    let binding = elastos_runtime::auth::ProofBinding::passkey_webauthn(
        elastos_runtime::auth::PasskeyWebAuthnBinding {
            credential_id: credential_id.to_string(),
            public_key: "protected-content-release-test-public-key".to_string(),
            sign_count: 1,
            user_verified: true,
            origin: "https://elastos.elacitylabs.com".to_string(),
            rp_id: "elastos.elacitylabs.com".to_string(),
            created_at: now,
            last_used_at: now,
            revoked_at: None,
        },
    );
    crate::auth::upsert_principal_for_binding_as_role_named(
        data_dir,
        binding,
        principal_id.to_string(),
        crate::auth::RuntimePrincipalRole::Admin,
        None,
        now,
    )
    .unwrap()
    .proof_binding_id
}

#[cfg(unix)]
fn install_profile_authority_keeping_device_key(
    data_dir: &Path,
    principal_id: &str,
) -> (String, ProfileIdentityV1) {
    let proof_binding_id =
        store_profile_signing_passkey(data_dir, principal_id, "credential-protected-content");
    crate::auth::store_test_principal_root_protection(data_dir, principal_id);
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let profile = crate::collaboration_profile_authority::update_profile_authority(
        data_dir,
        principal_id,
        &localhost_root,
        &proof_binding_id,
        "Protected Content Test",
        None,
        crate::auth::now_ts(),
    )
    .unwrap();
    let profile_key = crate::crypto::decode_did_key(&profile.document().profile_did).unwrap();
    let profile_identity =
        ProfileIdentityV1::from_public_key_bytes(profile_key.to_bytes()).unwrap();
    (proof_binding_id, profile_identity)
}

#[cfg(unix)]
fn load_profile_did_for_test(data_dir: &Path, principal_id: &str) -> String {
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    crate::collaboration_profile_authority::load_profile_authority(
        data_dir,
        principal_id,
        &localhost_root,
    )
    .unwrap()
    .unwrap()
    .document()
    .profile_did
    .clone()
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
        "schema": super::RUNTIME_PURCHASE_SCHEMA_V1,
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
    let decoded: super::RuntimeCustodyPurchaseRecord =
        serde_json::from_value(legacy).expect("a legacy purchase record must still decode");
    assert_eq!(
        decoded.acquisition,
        super::RuntimeCustodyAcquisitionV1::Bought
    );
    assert_eq!(decoded.acquisition_stage.stage, "buy");
    assert_eq!(decoded.acquisition_stage.value, "0x1");
}

fn persist_runtime_custody_purchase_for_mint(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    principal_id: &str,
    profile_did: &str,
    now: u64,
) -> RuntimeCustodyPurchaseRecord {
    let listing = super::load_runtime_custody_listing(data_dir, mint.draft().mint_id())
        .unwrap()
        .expect("runtime custody listing");
    let wallet_binding = ValidatedChainOutcomeBindingV1::ManagedSigned {
        signed_transaction_sha256: format!("sha256:{}", hex::encode([0xab; 32])),
    };
    let chain_transaction = format!("0x{}", hex::encode([0xaa; 32]));
    let chain_observation = json!({
        "schema": "elastos.chain.broadcast_receipt/v1",
        "network": "esc-mainnet",
    });
    let record = RuntimeCustodyPurchaseRecord {
        schema: RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
        principal_id: principal_id.to_string(),
        profile_did: profile_did.to_string(),
        mint_id: hex::encode(mint.draft().mint_id().as_bytes()),
        content_id: runtime_protected_content_id(mint.draft().encrypted_content()).unwrap(),
        cid: mint
            .content_availability()
            .unwrap()
            .content_cid()
            .to_string(),
        listing_sha256: listing.portable_package_digest(),
        seller_address: listing.package.seller_address.clone(),
        chain_namespace: listing.package.chain_namespace.clone(),
        network: listing.package.network.clone(),
        ledger: listing.package.ledger.clone(),
        token_id: listing.package.token_id.clone(),
        operative: listing.package.operative.clone(),
        price: listing.package.price.clone(),
        pay_token: listing.package.pay_token.clone(),
        payment_processor: listing.package.payment_processor.clone(),
        availability_receipt_digest: format!(
            "sha256:{}",
            hex::encode(
                mint.content_availability()
                    .unwrap()
                    .receipt_digest()
                    .as_bytes()
            )
        ),
        account_id: "wallet-account-alpha".to_string(),
        address: wallet_address_hex(wallet(7)),
        approval_stage: None,
        acquisition: super::RuntimeCustodyAcquisitionV1::Bought,
        capsule_uri: None,
        acquisition_stage: RuntimeCustodyPurchaseStageRecord {
            stage: "buy".to_string(),
            effect_id: "runtime-effect:11111111111111111111111111111111".to_string(),
            approval_request_id: "wallet-request:11111111111111111111111111111111".to_string(),
            request_sha256: format!("sha256:{}", hex::encode([0xac; 32])),
            chain_namespace: listing.package.chain_namespace.clone(),
            network: listing.package.network.clone(),
            to: "0x2222222222222222222222222222222222222222".to_string(),
            value: "0x1".to_string(),
            data: "0x".to_string(),
        },
        progress: RuntimeCustodyPurchaseProgress::Complete {
            terminal: RuntimeCustodyTerminalPurchaseRecord {
                chain_transaction,
                wallet_binding,
                chain_observation,
                access_evidence: Some(RuntimeCustodyPurchaseAccessEvidenceRecord {
                    schema: "elastos.chain.protected-content-purchase-access/v1".to_string(),
                    request_id: "purchase-access:test".to_string(),
                    network: listing.package.network.clone(),
                    chain_id: 8453,
                    wallet: wallet_address_hex(wallet(7)),
                    content_access_id: Some(listing.package.content_access_id.clone()),
                    ledger: None,
                    token_id: None,
                    has_access: true,
                    finalized_block_number: 44,
                    finalized_block_hash: format!("0x{}", hex::encode([0xad; 32])),
                    finalized_block_timestamp: now,
                    observed_at: now,
                }),
                confirmed_at: now,
                acquired_at: now,
            },
        },
        created_at: now,
        updated_at: now,
    };
    write_owner_only_bytes(
        &runtime_purchase_path(data_dir, principal_id, mint.draft().mint_id()),
        &serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    record
}

#[cfg(unix)]
#[allow(
    clippy::too_many_arguments,
    reason = "test helper binds every fixture fact explicitly"
)]
fn persist_runtime_custody_active_viewer_for_purchase(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    purchase: &RuntimeCustodyPurchaseRecord,
    proof_binding_id: &str,
    session_id: &str,
    grant_id: &str,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
) -> RuntimeViewerSession {
    let binding = super::derive_runtime_custody_session_binding(
        &purchase.principal_id,
        &purchase.profile_did,
        TEST_VIEWER_EXECUTABLE_ACTOR,
        TEST_VIEWER_LAUNCH_ID,
        proof_binding_id,
        session_id,
        grant_id,
        mint.draft().mint_id(),
    )
    .unwrap();
    let session = RuntimeViewerSession::from_persisted_parts(
        digest(0x91),
        handle,
        mint.draft().encrypted_content().clone(),
        RightsActionV1::View,
        expires_at,
    )
    .unwrap();
    let record = super::RuntimeCustodyViewerRecord::from_active_session(
        &purchase.principal_id,
        &purchase.profile_did,
        mint.draft().mint_id(),
        &purchase.content_id,
        binding,
        &session,
        crate::auth::now_ts(),
    )
    .unwrap();
    super::persist_runtime_custody_viewer_record(
        data_dir,
        &purchase.principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();
    session
}

#[cfg(unix)]
#[allow(
    clippy::too_many_arguments,
    reason = "test helper binds every fixture fact explicitly"
)]
fn persist_runtime_custody_open_pending_viewer_for_purchase(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    purchase: &RuntimeCustodyPurchaseRecord,
    proof_binding_id: &str,
    session_id: &str,
    grant_id: &str,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
) -> super::RuntimeCustodyViewerRecord {
    let binding = super::derive_runtime_custody_session_binding(
        &purchase.principal_id,
        &purchase.profile_did,
        TEST_VIEWER_EXECUTABLE_ACTOR,
        TEST_VIEWER_LAUNCH_ID,
        proof_binding_id,
        session_id,
        grant_id,
        mint.draft().mint_id(),
    )
    .unwrap();
    let record = super::RuntimeCustodyViewerRecord::from_open_pending(
        super::RuntimeCustodyOpenPendingInput {
            principal_id: &purchase.principal_id,
            profile_did: &purchase.profile_did,
            mint_id: mint.draft().mint_id(),
            content_id: &purchase.content_id,
            runtime_session_binding: binding,
            audit_request_id: digest(0x91),
            viewer_session_handle: handle,
            expires_at,
            now: crate::auth::now_ts(),
        },
    )
    .unwrap();
    super::persist_runtime_custody_viewer_record(
        data_dir,
        &purchase.principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();
    record
}

#[cfg(unix)]
fn install_profile_authority_for_release_test(
    data_dir: &Path,
    principal_id: &str,
) -> (String, String, ProfileIdentityV1) {
    owner_only_dir(data_dir);
    write_device_key(data_dir, 0x42);
    let proof_binding_id =
        store_profile_signing_passkey(data_dir, principal_id, "credential-protected-content");
    crate::auth::store_test_principal_root_protection(data_dir, principal_id);
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let profile = crate::collaboration_profile_authority::update_profile_authority(
        data_dir,
        principal_id,
        &localhost_root,
        &proof_binding_id,
        "Protected Content Test",
        None,
        NOW,
    )
    .unwrap();
    let profile_key = crate::crypto::decode_did_key(&profile.document().profile_did).unwrap();
    let profile_identity =
        ProfileIdentityV1::from_public_key_bytes(profile_key.to_bytes()).unwrap();
    (proof_binding_id, localhost_root, profile_identity)
}

fn release_operation_assembly_input(
    profile: ProfileIdentityV1,
) -> super::RuntimeReleaseOperationAssemblyInput {
    let envelope = custody_envelope_for_media(0x11);
    let policy = policy_body();
    let binding = ProtectedContentBindingV1::new(
        envelope.manifest().encrypted_content().clone(),
        envelope.key_envelope_identity().unwrap(),
        policy.policy_identity().unwrap(),
        profile,
        wallet(7),
        RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
    )
    .unwrap();
    let recipient_public_key = recipient_public_key(0x30);
    let recipient_identity = recipient_identity(0x30);
    let rights_request = {
        let request = elastos_protected_content_contracts::RightsRequestV1::new(
            binding.clone(),
            RightsActionV1::View,
            recipient_identity.clone(),
            NOW,
            NOW + 180,
            ReplayNonce16::new([0x55; 16]),
        )
        .unwrap();
        let key = WalletSigningKey::from_slice(&[7; 32]).unwrap();
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&request.signing_hash().unwrap())
            .unwrap();
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte());
        WalletSignedRightsRequestV1::new(request, signature_bytes).unwrap()
    };
    let release_request = KeyReleaseRequestV1::new(
        binding.clone(),
        rights_request.request().request_hash().unwrap(),
        RightsActionV1::View,
        recipient_identity.clone(),
        NOW + 1,
        NOW + 50,
        ReplayNonce16::new([0x66; 16]),
    )
    .unwrap();
    super::RuntimeReleaseOperationAssemblyInput {
        rights_request,
        release_request,
        recipient_public_key,
        recipient_identity,
        policy_body: policy.clone(),
        evidence_request: RightsEvaluationEvidenceRequestV1::new(
            binding,
            policy.policy_identity().unwrap(),
        )
        .unwrap(),
        custody_epoch: signed_custody_epoch(),
        audit_request_id: RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
        issued_at: NOW + 2,
        expires_at: NOW + 40,
    }
}

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

    let operation = super::assemble_protected_content_runtime_release_operation(
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
    let duplicate = super::assemble_protected_content_runtime_release_operation(
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

    assert!(super::assemble_protected_content_runtime_release_operation(
        directory.path(),
        principal_id,
        &localhost_root,
        "proof:passkey:missing-protected-content-release",
        release_operation_assembly_input(profile),
        NOW + 3,
    )
    .is_err());

    let foreign_proof = store_profile_signing_passkey(
        directory.path(),
        "person:local:foreign-protected-content-release",
        "credential-foreign-protected-content",
    );
    assert!(super::assemble_protected_content_runtime_release_operation(
        directory.path(),
        principal_id,
        &localhost_root,
        &foreign_proof,
        release_operation_assembly_input(profile),
        NOW + 3,
    )
    .is_err());
    crate::auth::revoke_passkey_binding(directory.path(), &proof_binding_id, NOW + 4).unwrap();
    assert!(super::assemble_protected_content_runtime_release_operation(
        directory.path(),
        principal_id,
        &localhost_root,
        &proof_binding_id,
        release_operation_assembly_input(profile),
        NOW + 4,
    )
    .is_err());
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
    let policy = super::ResolvedRuntimeRightsPolicy {
        identity: assembly.policy_body.policy_identity().unwrap(),
        body: assembly.policy_body.clone(),
    };
    let input = super::RuntimeViewerReleaseOperationInput {
        data_dir: directory.path(),
        principal_id,
        proof_binding_id: &proof_binding_id,
        signed_rights: &assembly.rights_request,
        prepared: &prepared,
        policy: &policy,
        custody_epoch: &assembly.custody_epoch,
        audit_request_id: assembly.audit_request_id,
    };

    let first = super::runtime_viewer_release_operation_at(&input, NOW + 10).unwrap();
    let rebuilt = super::runtime_viewer_release_operation_at(&input, NOW + 100).unwrap();

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
    let error = super::assemble_protected_content_runtime_release_operation(
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
    assert!(super::assemble_protected_content_runtime_release_operation(
        missing_profile.path(),
        missing_profile_principal,
        &crate::auth::principal_localhost_root(missing_profile_principal),
        &missing_profile_proof,
        release_operation_assembly_input(other_profile),
        NOW + 3,
    )
    .is_err());

    let missing_device = tempfile::tempdir().unwrap();
    let missing_device_principal = "person:local:missing-device-release";
    let (proof_binding_id, localhost_root, profile) =
        install_profile_authority_for_release_test(missing_device.path(), missing_device_principal);
    fs::remove_file(missing_device.path().join("identity/device.key")).unwrap();
    assert!(super::assemble_protected_content_runtime_release_operation(
        missing_device.path(),
        missing_device_principal,
        &localhost_root,
        &proof_binding_id,
        release_operation_assembly_input(profile),
        NOW + 3,
    )
    .is_err());

    let mismatch = tempfile::tempdir().unwrap();
    let mismatch_principal = "person:local:mismatched-profile-release";
    let (proof_binding_id, localhost_root, _) =
        install_profile_authority_for_release_test(mismatch.path(), mismatch_principal);
    assert!(super::assemble_protected_content_runtime_release_operation(
        mismatch.path(),
        mismatch_principal,
        &localhost_root,
        &proof_binding_id,
        release_operation_assembly_input(other_profile),
        NOW + 3,
    )
    .is_err());
}

fn make_signed_runtime_release_operation_for_envelope_and_seed(
    seed: u8,
    envelope: &CustodyEnvelopeV1,
) -> SignedRuntimeReleaseOperationV1 {
    make_signed_runtime_release_operation_for_envelope_and_epoch_at(
        seed,
        envelope,
        signed_custody_epoch(),
        NOW,
    )
}

fn make_signed_runtime_release_operation_for_envelope_and_epoch_at(
    seed: u8,
    envelope: &CustodyEnvelopeV1,
    custody_epoch: SignedCustodyEpochV1,
    now: u64,
) -> SignedRuntimeReleaseOperationV1 {
    make_signed_runtime_release_operation_for_envelope_and_epoch_and_recipient_at(
        seed,
        envelope,
        custody_epoch,
        recipient_public_key(0x30),
        recipient_identity(0x30),
        RuntimeReleaseAuditIdV1::new(digest(0x91 ^ seed)).unwrap(),
        now,
    )
}

fn make_signed_runtime_release_operation_for_envelope_and_epoch_and_recipient_at(
    seed: u8,
    envelope: &CustodyEnvelopeV1,
    custody_epoch: SignedCustodyEpochV1,
    recipient_public: RecipientPublicKeyBytesV1,
    recipient_identity: RecipientKeyIdentityV1,
    audit_request_id: RuntimeReleaseAuditIdV1,
    now: u64,
) -> SignedRuntimeReleaseOperationV1 {
    let runtime_key = SigningKey::from_bytes(&[seed; 32]);
    let binding = binding_for_envelope(envelope);
    let rights_request = {
        let request = elastos_protected_content_contracts::RightsRequestV1::new(
            binding.clone(),
            RightsActionV1::View,
            recipient_identity.clone(),
            now.saturating_sub(5),
            now + 180,
            ReplayNonce16::new([0x55; 16]),
        )
        .unwrap();
        let key = WalletSigningKey::from_slice(&[7; 32]).unwrap();
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&request.signing_hash().unwrap())
            .unwrap();
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte());
        WalletSignedRightsRequestV1::new(request, signature_bytes).unwrap()
    };
    let release_request = KeyReleaseRequestV1::new(
        binding.clone(),
        rights_request.request().request_hash().unwrap(),
        RightsActionV1::View,
        rights_request.request().recipient().clone(),
        now.saturating_sub(4),
        now + 56,
        ReplayNonce16::new([0x66; 16]),
    )
    .unwrap();
    let profile = SigningKey::from_bytes(&[0x26; 32]);
    let authorization_statement = RecipientKeyAuthorizationStatementV1::new(
        binding.clone(),
        RightsActionV1::View,
        recipient_public,
        rights_request.request().recipient().clone(),
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        now.saturating_sub(5),
        now + 120,
    )
    .unwrap();
    let authorization = SignedRecipientKeyAuthorizationV1::new(
        authorization_statement.clone(),
        profile
            .sign(&authorization_statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let policy = policy_body();
    let evidence_request =
        elastos_protected_content_contracts::RightsEvaluationEvidenceRequestV1::new(
            binding.clone(),
            policy.policy_identity().unwrap(),
        )
        .unwrap();
    let statement = RuntimeReleaseOperationStatementV1::new(
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        rights_request,
        release_request,
        recipient_public,
        authorization,
        policy,
        evidence_request,
        custody_epoch,
        audit_request_id,
        now.saturating_sub(3),
        now + 55,
    )
    .unwrap();
    SignedRuntimeReleaseOperationV1::new(
        statement.clone(),
        runtime_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn wallet_request_response_for_release_at(
    operation: &SignedRuntimeReleaseOperationV1,
    profile: &str,
    account_id: &str,
    request_id: &str,
    now: u64,
) -> (Vec<u8>, Vec<u8>) {
    wallet_request_response_for_release_context_at(
        operation,
        profile,
        "runtime-session:alpha",
        Some("proof:alpha"),
        "grant:alpha",
        "launch:alpha",
        account_id,
        request_id,
        now,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "test helper binds every fixture fact explicitly"
)]
fn wallet_request_response_for_release_context_at(
    operation: &SignedRuntimeReleaseOperationV1,
    profile: &str,
    runtime_session_id: &str,
    proof_binding: Option<&str>,
    grant_id: &str,
    launch_id: &str,
    account_id: &str,
    request_id: &str,
    now: u64,
) -> (Vec<u8>, Vec<u8>) {
    let context = VerifiedWalletInvocationContext::new(
        profile,
        runtime_session_id,
        proof_binding.map(str::to_string),
        grant_id,
        "runtime",
        launch_id,
    )
    .unwrap();
    let request = WalletProviderRequestV2::new(
        &context,
        request_id,
        now,
        now + 120,
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            account_id: account_id.to_string(),
            canonical_rights_request_hex: hex::encode(
                operation
                    .statement()
                    .rights_request()
                    .request()
                    .canonical_bytes()
                    .unwrap(),
            ),
            reason: "Open protected content".to_string(),
        },
    )
    .unwrap();
    let result = ProtectedContentRightsSignatureResultV1::new(
        account_id,
        wallet_address_hex(
            operation
                .statement()
                .rights_request()
                .request()
                .binding()
                .wallet(),
        ),
        hex::encode(
            operation
                .statement()
                .rights_request()
                .canonical_bytes()
                .unwrap(),
        ),
    )
    .unwrap();
    let response = WalletProviderResponseV2::for_request(
        &request,
        WalletResultV2::Ok {
            data: serde_json::to_value(result).unwrap(),
        },
    );
    (
        serde_json::to_vec(&request).unwrap(),
        serde_json::to_vec(&response).unwrap(),
    )
}

fn signed_runtime_custody_provisioning_at(
    record: &CustodyNodeProvisioningRecordV1,
    runtime_seed: u8,
    now: u64,
) -> SignedRuntimeCustodyProvisioningV1 {
    let runtime_key = SigningKey::from_bytes(&[runtime_seed; 32]);
    let statement = RuntimeCustodyProvisioningStatementV1::new(
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        record.record_identity().unwrap(),
        RuntimeCustodyProvisioningIdV1::new(digest(0xa5)).unwrap(),
        now.saturating_sub(5),
        now + 40,
    )
    .unwrap();
    SignedRuntimeCustodyProvisioningV1::new(
        statement.clone(),
        runtime_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn chain_evidence_for_request_at(
    request: &RightsProviderRequestV1,
    now_unix_seconds: u64,
    evidence_now: u64,
    has_access: bool,
) -> Value {
    let validated = ValidatedRightsProviderRequestV1::decode_and_validate_at(
        &request.to_json_vec().unwrap(),
        now_unix_seconds,
    )
    .unwrap();
    let authenticated = validated
        .authenticated_runtime_release_operation()
        .as_v1()
        .expect("these fixtures are V1 operations");
    let policy = authenticated.statement().policy_body();
    let evidence_request = authenticated.statement().evidence_request();
    let evidence_issued_at = evidence_now.saturating_sub(1);
    let evidence = RightsEvaluationEvidenceV1::new(
        authenticated.operation_hash(),
        authenticated.release_request_hash(),
        evidence_request.binding().clone(),
        evidence_request.policy_identity().clone(),
        evidence_request.binding().wallet(),
        policy.chain_id(),
        100,
        digest(0x88),
        has_access,
        evidence_issued_at,
        evidence_issued_at + MAX_RIGHTS_EVIDENCE_LIFETIME_SECS,
    )
    .unwrap();
    let bytes = evidence.canonical_bytes().unwrap();
    json!({
        "schema": "elastos.chain.protected-content-rights-evidence/v1",
        "chain_id": evidence.observed_chain_id(),
        "finalized_block_number": evidence.finalized_block_number(),
        "finalized_block_hash": format!(
            "0x{}",
            hex::encode(evidence.finalized_block_hash().as_bytes())
        ),
        "rights_evaluation_evidence": format!("0x{}", hex::encode(&bytes)),
        "rights_evaluation_evidence_hash": format!(
            "0x{}",
            hex::encode(evidence.canonical_hash().unwrap().as_bytes())
        ),
    })
}

fn make_signed_node_rights_decision(
    operation: &SignedRuntimeReleaseOperationV1,
    node_seed: u8,
    decision: RightsDecisionV1,
) -> SignedNodeRightsDecisionV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), NOW + 3)
        .unwrap();
    let statement = elastos_protected_content_contracts::NodeRightsDecisionStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.rights_request_hash(),
        authenticated.binding().clone(),
        authenticated.action(),
        node_public_key(node_seed),
        decision,
        digest(0x80 ^ node_seed),
        NOW + 4,
        NOW + 40,
    )
    .unwrap();
    SignedNodeRightsDecisionV1::new(
        statement.clone(),
        node_signing_key(node_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn make_signed_node_contribution(
    operation: &SignedRuntimeReleaseOperationV1,
    node_seed: u8,
) -> SignedNodeContributionV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), NOW + 5)
        .unwrap();
    let decision =
        make_signed_node_rights_decision(operation, node_seed, RightsDecisionV1::Allowed);
    let sealed =
        RecipientSealedContributionV1::new(authenticated.recipient().clone(), vec![node_seed; 96])
            .unwrap();
    let statement = NodeContributionStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.binding().clone(),
        decision,
        sealed,
        NOW + 5,
        NOW + 40,
    )
    .unwrap();
    SignedNodeContributionV1::new(
        statement.clone(),
        node_signing_key(node_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn make_signed_terminal_receipt(
    operation: &SignedRuntimeReleaseOperationV1,
    contributions: &[SignedNodeContributionV1],
    issuer_seed: u8,
) -> SignedTerminalReceiptV1 {
    make_signed_terminal_receipt_at(operation, contributions, issuer_seed, NOW + 6)
}

fn make_signed_terminal_receipt_at(
    operation: &SignedRuntimeReleaseOperationV1,
    contributions: &[SignedNodeContributionV1],
    issuer_seed: u8,
    now: u64,
) -> SignedTerminalReceiptV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), now)
        .unwrap();
    let node_set = operation
        .statement()
        .custody_epoch()
        .statement()
        .node_set()
        .unwrap();
    let verified_contributions = contributions
        .iter()
        .map(|contribution| {
            authenticated
                .verify_node_contribution(contribution, &node_set, now)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let refs = verified_contributions
        .iter()
        .map(NodeContributionRefV1::from)
        .collect::<Vec<_>>();
    let expires_at = contributions
        .iter()
        .map(|contribution| contribution.statement().expires_at())
        .min()
        .unwrap_or_else(|| now.saturating_add(34))
        .min(now.saturating_add(34));
    let issuer_key = SigningKey::from_bytes(&[issuer_seed; 32]);
    let statement = TerminalReceiptStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.binding().clone(),
        TerminalReceiptIssuerKey::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        KeyReleaseOutcomeV1::Released,
        refs,
        now,
        expires_at,
    )
    .unwrap();
    SignedTerminalReceiptV1::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn provisioning_record_for_selected_node(
    envelope: &CustodyEnvelopeV1,
    selected_node_public_key: NodePublicKey,
) -> CustodyNodeProvisioningRecordV1 {
    CustodyNodeProvisioningRecordV1::new(
        envelope.key_envelope_identity().unwrap(),
        envelope.manifest().clone(),
        selected_node_public_key,
        envelope
            .stored_share_for_node(selected_node_public_key)
            .unwrap()
            .clone(),
    )
    .unwrap()
}

fn opaque_handle(seed: u8) -> [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1] {
    let mut bytes = [0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    bytes[0] = seed.max(1);
    bytes[31] = seed ^ 0x5a;
    bytes
}

fn decrypt_prepare_request() -> DecryptProviderRequestV1 {
    let envelope = custody_envelope_for_media(0x11);
    DecryptProviderRequestV1::new_prepare_recipient(
        &binding_for_envelope(&envelope),
        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
        RightsActionV1::View,
        runtime_operation_issuer_for_seed(0x42),
        NOW,
        NOW + 50,
    )
    .unwrap()
}

fn decrypt_open_fixture() -> (
    DecryptProviderRequestV1,
    RuntimeReleaseAuditIdV1,
    [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    Vec<u8>,
    Vec<Vec<u8>>,
) {
    let envelope = custody_envelope_for_media(0x11);
    let operation = make_signed_runtime_release_operation_for_envelope_and_seed(0x42, &envelope);
    let contributions = vec![
        make_signed_node_contribution(&operation, 1),
        make_signed_node_contribution(&operation, 2),
    ];
    let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
    let handle = opaque_handle(0x21);
    let (init_segment, encrypted_segments) = media_components(0x11);
    let media = media_identity(0x11);
    let request = DecryptProviderRequestV1::new_open_viewer_session(
        handle,
        &operation,
        terminal.statement().issuer(),
        envelope.manifest().content_key_commitment(),
        &media,
        &init_segment,
        &contributions,
        &terminal,
    )
    .unwrap();
    (
        request,
        operation.statement().audit_request_id(),
        handle,
        init_segment,
        encrypted_segments,
    )
}

fn assert_exact_runtime_decrypt_invocation(
    recorded: &Value,
    expected_op: &str,
    expected_request: &Value,
) {
    assert_eq!(recorded["op"], expected_op);
    assert_eq!(
        recorded["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["target"],
        PROTECTED_CONTENT_DECRYPT_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert_eq!(recorded["_runtime_invocation"]["carrier"], Value::Null);
    assert!(recorded.get("route").is_none());
    assert!(recorded.get("host").is_none());
    assert!(recorded.get("port").is_none());
    assert!(recorded.get("url").is_none());
    let mut stripped = recorded.clone();
    stripped
        .as_object_mut()
        .unwrap()
        .remove("_runtime_invocation");
    assert_eq!(&stripped, expected_request);
}

#[cfg(unix)]
struct ProcessCustodyNodeFixture {
    registry: Arc<ProviderRegistry>,
    adapter: RuntimeCustodyRegistryAdapter,
    provisioned: ProvisionedCustodyProviderPublicKeys,
    owner_state_root: Digest32,
}

#[cfg(unix)]
fn provisioned_process_custody_node_for_issuer(
    binary: &Path,
    temp_root: &Path,
    dir_name: &str,
    runtime_issuer: RuntimeOperationIssuerKeyV1,
    owner_state_root: Digest32,
) -> ProcessCustodyNodeFixture {
    let data_dir = temp_root.join(dir_name);
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(state_root.parent().unwrap());
    let provisioned =
        provision_custody_node_public_receipt_for_issuer(binary, &state_root, runtime_issuer);
    let registry = Arc::new(ProviderRegistry::new());
    ProcessCustodyNodeFixture {
        adapter: RuntimeCustodyRegistryAdapter::new(
            registry.clone(),
            elastos_runtime::provider::ProviderInvocationTransport::Local,
            super::RuntimeCustodyCallDiagnostics::default(),
        ),
        registry,
        provisioned,
        owner_state_root,
    }
}

#[cfg(unix)]
fn provision_custody_node_public_receipt_for_issuer(
    binary: &Path,
    state_root: &Path,
    runtime_issuer: RuntimeOperationIssuerKeyV1,
) -> ProvisionedCustodyProviderPublicKeys {
    let issuer_hex = format!("0x{}", hex::encode(runtime_issuer.as_bytes()));
    let output = Command::new(binary)
        .args([
            "provision",
            "--base-path",
            state_root.to_str().unwrap(),
            "--trusted-runtime-issuer",
            &issuer_hex,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    parse_and_verify_provisioning_output(&response, runtime_issuer).unwrap()
}

#[cfg(unix)]
fn provisioned_process_custody_node(
    binary: &Path,
    temp_root: &Path,
    dir_name: &str,
    runtime_issuer_seed: u8,
    owner_state_root: Digest32,
) -> ProcessCustodyNodeFixture {
    let data_dir = temp_root.join(dir_name);
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(state_root.parent().unwrap());
    let provisioned =
        provision_custody_node_public_receipt(binary, &state_root, runtime_issuer_seed);
    let registry = Arc::new(ProviderRegistry::new());
    ProcessCustodyNodeFixture {
        adapter: RuntimeCustodyRegistryAdapter::new(
            registry.clone(),
            elastos_runtime::provider::ProviderInvocationTransport::Local,
            super::RuntimeCustodyCallDiagnostics::default(),
        ),
        registry,
        provisioned,
        owner_state_root,
    }
}

#[cfg(unix)]
async fn provision_selected_node_share(
    fixture: &ProcessCustodyNodeFixture,
    envelope: &CustodyEnvelopeV1,
    runtime_seed: u8,
    now: u64,
) {
    let provisioning_record =
        provisioning_record_for_selected_node(envelope, fixture.provisioned.node_public_key);
    let provisioning =
        signed_runtime_custody_provisioning_at(&provisioning_record, runtime_seed, now);
    let request =
        CustodyProviderRequestV1::new_provision_node_share(&provisioning_record, &provisioning)
            .unwrap();
    let response = fixture
        .adapter
        .provision_node_share(&request)
        .await
        .unwrap();
    assert_eq!(
        response.provisioned_record_identity().unwrap(),
        provisioning_record.record_identity().unwrap()
    );
}

#[cfg(unix)]
fn runtime_verified_purchase_effect_for_mint(
    mint: &PersistedRuntimeMint,
    principal_id: &str,
    account_id: &str,
    approval_request_id: &str,
    tx_byte: u8,
    now: u64,
) -> RuntimeVerifiedPurchaseEffect {
    RuntimeVerifiedPurchaseEffect::new(
        RuntimeProtectedContentPurchaseIntent::new(
            mint.draft().mint_id(),
            mint.draft().encrypted_content().clone(),
            mint.draft().key_envelope().clone(),
            mint.draft().policy().clone(),
            RightsActionV1::View,
            "eip155:20",
            "esc-mainnet",
            "0x2222222222222222222222222222222222222222",
            "0x1",
            "0x",
        )
        .unwrap(),
        RuntimePurchaseEffectAuthority::new(
            principal_id,
            account_id,
            wallet_address_hex(wallet(7)),
            approval_request_id,
        )
        .unwrap(),
        ValidatedChainOutcomeBindingV1::ManagedSigned {
            signed_transaction_sha256: format!("sha256:{}", hex::encode([tx_byte ^ 1; 32])),
        },
        format!("0x{}", hex::encode([tx_byte; 32])),
        json!({
            "schema": "elastos.chain.broadcast_receipt/v1",
            "network": "esc-mainnet",
        }),
        now,
    )
    .unwrap()
}

fn ok_provider_response(value: serde_json::Value) -> serde_json::Value {
    json!({
        "status": "ok",
        "data": value,
    })
}

fn ok_typed_protect_provider_response(response: ProtectProviderResponseV1) -> serde_json::Value {
    ok_provider_response(serde_json::from_slice(&response.to_json_vec().unwrap()).unwrap())
}

#[async_trait::async_trait]
impl Provider for RecordingProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "recording provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![self.name]
    }

    fn name(&self) -> &'static str {
        self.name
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        Ok(self.response.clone())
    }
}

#[async_trait::async_trait]
impl Provider for SequencedProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "sequenced provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![self.name]
    }

    fn name(&self) -> &'static str {
        self.name
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        self.responses.lock().await.pop_front().unwrap_or_else(|| {
            Err(ProviderError::Provider(
                "sequenced provider response queue is exhausted".to_string(),
            ))
        })
    }
}

#[async_trait::async_trait]
impl Provider for ProcessChainEvidenceProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "process chain evidence provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CHAIN_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CHAIN_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        let expected = elastos_protected_content_rights::chain_rights_evidence_request_any(
            &self
                .expected_request
                .signed_runtime_release_operation()
                .map_err(|_| {
                    ProviderError::Provider("expected rights request is invalid".to_string())
                })?,
        )
        .map_err(|_| ProviderError::Provider("expected rights request is invalid".to_string()))?;
        if request["_runtime_invocation"]["source"]
            != Value::String(RUNTIME_PROVIDER_ID.to_string())
            || request["_runtime_invocation"]["target"]
                != Value::String(CHAIN_PROVIDER_ID.to_string())
            || request["_runtime_invocation"]["op"]
                != Value::String(CHAIN_RIGHTS_EVIDENCE_OP.to_string())
            || request["_runtime_invocation"]["transport"]
                != Value::String("runtime-local-provider-plane".to_string())
            || request["_runtime_invocation"]["carrier"] != Value::Null
        {
            return Err(ProviderError::Provider(
                "chain evidence runtime envelope did not match the expected invocation".to_string(),
            ));
        }
        let mut inner_request = request.clone();
        let Some(inner_object) = inner_request.as_object_mut() else {
            return Err(ProviderError::Provider(
                "chain evidence request was not an object".to_string(),
            ));
        };
        inner_object.remove("_runtime_invocation");
        if inner_request != expected {
            return Err(ProviderError::Provider(
                "chain evidence request did not match the expected release operation".to_string(),
            ));
        }
        let evidence_now = crate::auth::now_ts();
        Ok(ok_provider_response(chain_evidence_for_request_at(
            &self.expected_request,
            evidence_now,
            evidence_now,
            self.has_access,
        )))
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl Provider for TestMediaPreparationProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "test media provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![MEDIA_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        MEDIA_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let operation_id = request
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing operation id".to_string()))?
            .to_string();
        if request["op"] != "prepare"
            || request["_runtime_invocation"]["source"] != RUNTIME_PROVIDER_ID
            || request["_runtime_invocation"]["target"] != MEDIA_PROVIDER_ID
            || request["_runtime_invocation"]["op"] != "prepare"
            || request["_runtime_invocation"]["transport"] != "runtime-local-provider-plane"
            || request["_runtime_invocation"]["carrier"] != Value::Null
        {
            return Err(ProviderError::Provider(
                "media preparation invocation authority is invalid".to_string(),
            ));
        }
        self.requests.lock().await.push(operation_id.clone());
        match self.response {
            TestMediaPreparationResponse::Prepared(renditions) => {
                write_prepared_media_v2(
                    &self.staging_root.join(operation_id),
                    &renditions
                        .iter()
                        .map(|rendition| (rendition.kind, rendition.segments))
                        .collect::<Vec<_>>(),
                );
                Ok(ok_provider_response(json!({
                    "schema": "elastos.media-provider.prepared-media/v2",
                    "renditions": renditions.iter().map(|rendition| json!({
                        "rendition": test_rendition_name(rendition.kind),
                        "mime_type": rendition.mime_type,
                        "codecs": rendition.codecs,
                        "segment_count": rendition.segments,
                    })).collect::<Vec<_>>(),
                })))
            }
            TestMediaPreparationResponse::SettledFailure => Ok(json!({
                "status": "error",
                "code": "internal_error",
                "message": "media preparation failed",
                "data": {"operation_settled": true},
            })),
            TestMediaPreparationResponse::UnknownSettlement => Err(ProviderError::Provider(
                "media preparation transport failed".to_string(),
            )),
        }
    }
}

#[cfg(unix)]
fn owner_only_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
fn test_rendition_name(kind: CencDashRenditionKindV2) -> &'static str {
    match kind {
        media_dash_fixture::V => "video",
        media_dash_fixture::A => "audio",
    }
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Lays out a media provider's v2 output under `operation_root`:
/// `prepared/<rendition>/init.mp4` and `segments/NNNNNNNN.m4s`, owner-only,
/// from the fixture's contiguous clear media.
#[cfg(unix)]
fn write_prepared_media_v2(operation_root: &Path, renditions: &[(CencDashRenditionKindV2, usize)]) {
    let prepared_root = operation_root.join("prepared");
    owner_only_dir(&prepared_root);
    for (kind, segments) in renditions {
        let rendition_dir = prepared_root.join(test_rendition_name(*kind));
        owner_only_dir(&rendition_dir);
        write_private_file(
            &rendition_dir.join("init.mp4"),
            &media_dash_fixture::init(*kind, 1),
        );
        let segments_dir = rendition_dir.join("segments");
        owner_only_dir(&segments_dir);
        for (index, segment) in media_dash_fixture::clear_segments(*kind, *segments)
            .iter()
            .enumerate()
        {
            write_private_file(&segments_dir.join(format!("{index:08}.m4s")), segment);
        }
    }
}

#[cfg(unix)]
fn protected_content_root(data_dir: &Path) -> PathBuf {
    data_dir.join("protected-content")
}

#[cfg(unix)]
fn custody_composition_config_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join("custody-composition.json")
}

#[cfg(unix)]
fn chain_provider_config_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join("chain-provider.json")
}

#[cfg(unix)]
fn write_chain_provider_config(data_dir: &Path, config: &Value) {
    owner_only_dir(&protected_content_root(data_dir));
    fs::write(
        chain_provider_config_path(data_dir),
        serde_json::to_vec(config).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        chain_provider_config_path(data_dir),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

#[cfg(unix)]
fn safe_ancestor_tempdir() -> tempfile::TempDir {
    // The media prerequisite import walks every ancestor of the source tool
    // path and rejects world-writable directories. std temp lives under
    // /tmp (mode 1777) on Linux, so fixtures built there are structurally
    // unsafe; anchor them under the build target dir, whose ancestors are
    // developer- or runner-owned.
    let root = option_env!("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target")));
    let base = root.join("media-prereq-test-fixtures");
    fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(&base).unwrap()
}

#[cfg(unix)]
fn write_media_prerequisite(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn media_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("protected-content/media-provider/config.json")
}

#[cfg(unix)]
fn prepare_test_media_prerequisite(data_dir: &Path, root: &Path) {
    owner_only_dir(root);
    write_media_prerequisite(&root.join("ffmpeg"), b"ffmpeg-private-test", 0o700);
    write_media_prerequisite(&root.join("ffprobe"), b"ffprobe-private-test", 0o700);
    prepare_runtime_media_provider_prerequisite(data_dir, root, MediaToolsTrust::MustMatch)
        .unwrap();
}

#[cfg(unix)]
#[test]
fn media_prerequisite_import_is_bounded_private_idempotent_and_never_executes_tools() {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().join("data");
    let source = temp.path().join("source:tools");
    let marker = temp.path().join("executed");
    owner_only_dir(&source);
    write_media_prerequisite(
        &source.join("ffmpeg"),
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes(),
        0o700,
    );
    write_media_prerequisite(
        &source.join("ffprobe"),
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes(),
        0o700,
    );

    prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
        .unwrap();
    let config_path = media_config_path(&data_dir);
    let original_config = fs::read(&config_path).unwrap();
    let original_ffmpeg =
        fs::read(data_dir.join("protected-content/media-provider/tools/ffmpeg")).unwrap();
    prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
        .unwrap();

    assert!(!marker.exists());
    assert_eq!(fs::read(&config_path).unwrap(), original_config);
    assert_eq!(
        fs::read(data_dir.join("protected-content/media-provider/tools/ffmpeg")).unwrap(),
        original_ffmpeg
    );
    let config: Value = serde_json::from_slice(&original_config).unwrap();
    assert_eq!(config["schema"], MEDIA_PROVIDER_CONFIG_SCHEMA_V1);
    assert_eq!(config["timeout_ms"], MEDIA_PROVIDER_TIMEOUT_MS_V1);
    assert_eq!(config["max_input_bytes"], MEDIA_PROVIDER_MAX_INPUT_BYTES_V1);
    assert_eq!(config["max_segment_count"], 512);
    assert_eq!(config["max_total_output_bytes"], 2u64 << 30);
    assert_eq!(
        fs::symlink_metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(fs::symlink_metadata(&config_path).unwrap().nlink(), 1);
    for name in ["ffmpeg", "ffprobe"] {
        let metadata = fs::symlink_metadata(
            data_dir
                .join("protected-content/media-provider/tools")
                .join(name),
        )
        .unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o500);
        assert_eq!(metadata.nlink(), 1);
    }
    let bridge = load_runtime_media_provider_bridge_config(&data_dir)
        .unwrap()
        .expect("generated config must survive restart validation");
    assert_eq!(bridge.extra["provider_id"], "media-provider");

    let mut bounded: Value = serde_json::from_slice(&original_config).unwrap();
    bounded["timeout_ms"] = json!(5_000);
    bounded["max_input_bytes"] = json!(1u64 << 20);
    let bounded_bytes = serde_json::to_vec_pretty(&bounded).unwrap();
    fs::write(&config_path, &bounded_bytes).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
        .unwrap();
    assert_eq!(fs::read(&config_path).unwrap(), bounded_bytes);

    // A differing pair without signed provenance is refused with nothing changed.
    let tools_dir = data_dir.join("protected-content/media-provider/tools");
    let imported_ffmpeg = fs::read(tools_dir.join("ffmpeg")).unwrap();
    let imported_probe = fs::read(tools_dir.join("ffprobe")).unwrap();
    write_media_prerequisite(&source.join("ffmpeg"), b"upgraded ffmpeg", 0o700);
    write_media_prerequisite(&source.join("ffprobe"), b"upgraded ffprobe", 0o700);
    let unchanged = |config: &[u8]| {
        assert_eq!(fs::read(&config_path).unwrap(), config);
        assert_eq!(fs::read(tools_dir.join("ffmpeg")).unwrap(), imported_ffmpeg);
        assert_eq!(fs::read(tools_dir.join("ffprobe")).unwrap(), imported_probe);
        assert_eq!(fs::read_dir(&tools_dir).unwrap().count(), 2);
    };
    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
            .unwrap_err();
    assert!(error
        .to_string()
        .contains("differ from the private imported pair"));
    unchanged(&bounded_bytes);

    // Bytes altered after the signed archive was verified are refused before any rename.
    let signed = MediaToolsTrust::SignedRelease(SignedMediaToolDigests {
        ffmpeg: sha2::Sha256::digest(b"upgraded ffmpeg").into(),
        ffprobe: sha2::Sha256::digest(b"upgraded ffprobe").into(),
    });
    write_media_prerequisite(&source.join("ffprobe"), b"tampered ffprobe", 0o700);
    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &source, signed).unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match the signed release media tools"));
    unchanged(&bounded_bytes);

    // A symlinked supplied tool is refused, whatever its target.
    let linked = temp.path().join("linked-source");
    owner_only_dir(&linked);
    write_media_prerequisite(&linked.join("real-ffprobe"), b"upgraded ffprobe", 0o700);
    std::os::unix::fs::symlink(linked.join("real-ffprobe"), linked.join("ffprobe")).unwrap();
    fs::copy(source.join("ffmpeg"), linked.join("ffmpeg")).unwrap();
    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &linked, signed).unwrap_err();
    assert!(error.to_string().contains("symbolic link"), "{error}");
    unchanged(&bounded_bytes);
    write_media_prerequisite(&source.join("ffprobe"), b"upgraded ffprobe", 0o700);
    let linked_dir = temp.path().join("linked-dir");
    std::os::unix::fs::symlink(&source, &linked_dir).unwrap();
    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &linked_dir, signed).unwrap_err();
    assert!(error.to_string().contains("symbolic link"), "{error}");
    unchanged(&bounded_bytes);
    // Even a root-owned system link (macOS /tmp or /var) on a supplied path is refused.
    if let Some(system_link) = ["/tmp", "/var", "/etc"]
        .into_iter()
        .map(Path::new)
        .find(|path| {
            fs::symlink_metadata(path)
                .is_ok_and(|meta| meta.file_type().is_symlink() && meta.uid() == 0)
        })
    {
        let error = prepare_runtime_media_provider_prerequisite(
            &data_dir,
            &system_link.join("media-tools"),
            signed,
        )
        .unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        unchanged(&bounded_bytes);
    }

    // The signed release's pair is re-imported and tuned limits are kept.
    write_media_prerequisite(&source.join("ffprobe"), b"upgraded ffprobe", 0o700);
    prepare_runtime_media_provider_prerequisite(&data_dir, &source, signed).unwrap();
    let upgraded = || {
        assert_eq!(fs::read(&config_path).unwrap(), bounded_bytes);
        assert_eq!(
            fs::read(tools_dir.join("ffmpeg")).unwrap(),
            b"upgraded ffmpeg"
        );
        assert_eq!(
            fs::read(tools_dir.join("ffprobe")).unwrap(),
            b"upgraded ffprobe"
        );
        for name in ["ffmpeg", "ffprobe"] {
            let metadata = fs::symlink_metadata(tools_dir.join(name)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o500);
            assert_eq!(metadata.nlink(), 1);
        }
        assert_eq!(fs::read_dir(&tools_dir).unwrap().count(), 2);
    };
    upgraded();
    let bridge = load_runtime_media_provider_bridge_config(&data_dir)
        .unwrap()
        .expect("upgraded config must survive restart validation");
    assert_eq!(bridge.extra["timeout_ms"], 5_000);

    // A pair left half-replaced by an interrupted run is repaired on rerun.
    let probe = tools_dir.join("ffprobe");
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&probe, &imported_probe).unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o500)).unwrap();
    prepare_runtime_media_provider_prerequisite(&data_dir, &source, signed).unwrap();
    upgraded();
}

#[cfg(unix)]
#[test]
fn media_source_accepts_group_writable_ancestors_and_keeps_file_guards() {
    let temp = safe_ancestor_tempdir();
    let shared = temp.path().join("group-shared");
    owner_only_dir(&shared);
    let tools = shared.join("tools");
    owner_only_dir(&tools);
    let tool = tools.join("ffmpeg");
    write_media_prerequisite(&tool, b"private executable", 0o700);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).unwrap();
    let mut source = super::open_runtime_media_tool(&tools, "ffmpeg").unwrap();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut source.file, &mut bytes).unwrap();
    assert_eq!(bytes, b"private executable");
    assert_eq!(fs::metadata(&shared).unwrap().mode() & 0o1777, 0o775);
    drop(source);

    for mode in [0o720, 0o777] {
        fs::set_permissions(&tool, fs::Permissions::from_mode(mode)).unwrap();
        assert!(super::open_runtime_media_tool(&tools, "ffmpeg").is_err());
        assert_eq!(fs::metadata(&tool).unwrap().mode() & 0o777, mode);
    }
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    for mode in [0o777, 0o1777] {
        fs::set_permissions(&shared, fs::Permissions::from_mode(mode)).unwrap();
        assert!(super::open_runtime_media_tool(&tools, "ffmpeg").is_err());
        assert_eq!(fs::metadata(&shared).unwrap().mode() & 0o1777, mode);
    }
    assert_eq!(fs::read(&tool).unwrap(), b"private executable");
}

#[cfg(unix)]
#[test]
fn media_prerequisite_rejects_missing_unsafe_and_oversized_tools_before_config() {
    let temp = safe_ancestor_tempdir();
    let missing_data = temp.path().join("missing-data");
    let missing = temp.path().join("missing-tools");
    owner_only_dir(&missing);
    write_media_prerequisite(&missing.join("ffmpeg"), b"ffmpeg", 0o700);
    let error = prepare_runtime_media_provider_prerequisite(
        &missing_data,
        &missing,
        MediaToolsTrust::MustMatch,
    )
    .unwrap_err();
    assert!(error.to_string().contains("ffprobe"));
    assert!(!media_config_path(&missing_data).exists());

    let unsafe_data = temp.path().join("unsafe-data");
    let unsafe_tools = temp.path().join("unsafe-tools");
    owner_only_dir(&unsafe_tools);
    write_media_prerequisite(&unsafe_tools.join("ffmpeg"), b"ffmpeg", 0o720);
    write_media_prerequisite(&unsafe_tools.join("ffprobe"), b"ffprobe", 0o700);
    assert!(prepare_runtime_media_provider_prerequisite(
        &unsafe_data,
        &unsafe_tools,
        MediaToolsTrust::MustMatch
    )
    .unwrap_err()
    .to_string()
    .contains("ffmpeg prerequisite"));
    assert!(!media_config_path(&unsafe_data).exists());

    let oversized_data = temp.path().join("oversized-data");
    let oversized_tools = temp.path().join("oversized-tools");
    owner_only_dir(&oversized_tools);
    let oversized = fs::File::create(oversized_tools.join("ffmpeg")).unwrap();
    oversized.set_len((512 * 1024 * 1024) + 1).unwrap();
    fs::set_permissions(
        oversized_tools.join("ffmpeg"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    write_media_prerequisite(&oversized_tools.join("ffprobe"), b"ffprobe", 0o700);
    assert!(prepare_runtime_media_provider_prerequisite(
        &oversized_data,
        &oversized_tools,
        MediaToolsTrust::MustMatch
    )
    .unwrap_err()
    .to_string()
    .contains("exceeds bounds"));
    assert!(!media_config_path(&oversized_data).exists());

    let non_file_data = temp.path().join("non-file-data");
    let non_file_tools = temp.path().join("non-file-tools");
    owner_only_dir(&non_file_tools);
    owner_only_dir(&non_file_tools.join("ffmpeg"));
    write_media_prerequisite(&non_file_tools.join("ffprobe"), b"ffprobe", 0o700);
    assert!(prepare_runtime_media_provider_prerequisite(
        &non_file_data,
        &non_file_tools,
        MediaToolsTrust::MustMatch
    )
    .unwrap_err()
    .to_string()
    .contains("ffmpeg prerequisite"));

    let unsafe_parent_data = temp.path().join("unsafe-parent-data");
    let unsafe_parent_tools = temp.path().join("unsafe-parent-tools");
    owner_only_dir(&unsafe_parent_tools);
    write_media_prerequisite(&unsafe_parent_tools.join("ffmpeg"), b"ffmpeg", 0o700);
    write_media_prerequisite(&unsafe_parent_tools.join("ffprobe"), b"ffprobe", 0o700);
    fs::set_permissions(&unsafe_parent_tools, fs::Permissions::from_mode(0o777)).unwrap();
    let refusal = prepare_runtime_media_provider_prerequisite(
        &unsafe_parent_data,
        &unsafe_parent_tools,
        MediaToolsTrust::MustMatch,
    )
    .unwrap_err()
    .to_string();
    assert!(
        refusal.contains("prerequisite parent is unsafe"),
        "{refusal}"
    );
    assert!(!refusal.contains("chmod"), "{refusal}");
    assert!(!refusal.contains("chown"), "{refusal}");
    assert_eq!(
        fs::metadata(&unsafe_parent_tools)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o777
    );

    let linked_data = temp.path().join("linked-data");
    let linked_tools = temp.path().join("linked-tools");
    owner_only_dir(&linked_tools);
    write_media_prerequisite(&linked_tools.join("ffmpeg"), b"ffmpeg", 0o700);
    fs::hard_link(
        linked_tools.join("ffmpeg"),
        linked_tools.join("ffmpeg-copy"),
    )
    .unwrap();
    write_media_prerequisite(&linked_tools.join("ffprobe"), b"ffprobe", 0o700);
    assert!(prepare_runtime_media_provider_prerequisite(
        &linked_data,
        &linked_tools,
        MediaToolsTrust::MustMatch
    )
    .unwrap_err()
    .to_string()
    .contains("ffmpeg prerequisite"));
}

#[cfg(unix)]
#[test]
fn media_prerequisite_rejects_links_modes_paths_and_unknown_config_fields_without_overwrite() {
    let temp = safe_ancestor_tempdir();
    let source = temp.path().join("source");
    let data_dir = temp.path().join("data");
    prepare_test_media_prerequisite(&data_dir, &source);
    let config_path = media_config_path(&data_dir);
    let valid = fs::read(&config_path).unwrap();

    let mut unknown: Value = serde_json::from_slice(&valid).unwrap();
    unknown["credential"] = json!("private-value");
    fs::write(&config_path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let error = load_runtime_media_provider_bridge_config(&data_dir).unwrap_err();
    assert!(!error.to_string().contains("private-value"));
    assert_eq!(
        fs::read(&config_path).unwrap(),
        serde_json::to_vec(&unknown).unwrap()
    );

    fs::write(&config_path, &valid).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&data_dir).is_err());
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let config_copy = data_dir.join("protected-content/media-provider/config-copy");
    fs::hard_link(&config_path, &config_copy).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&data_dir).is_err());
    fs::remove_file(config_copy).unwrap();

    let mut escaped: Value = serde_json::from_slice(&valid).unwrap();
    escaped["ffmpeg_path"] = json!("/private/tmp/ffmpeg");
    fs::write(&config_path, serde_json::to_vec(&escaped).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&data_dir).is_err());

    fs::write(&config_path, &valid).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let ffmpeg = data_dir.join("protected-content/media-provider/tools/ffmpeg");
    let ffmpeg_target = data_dir.join("protected-content/media-provider/tools/ffmpeg-target");
    fs::rename(&ffmpeg, &ffmpeg_target).unwrap();
    std::os::unix::fs::symlink(&ffmpeg_target, &ffmpeg).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&data_dir).is_err());

    let symlink_data = temp.path().join("symlink-data");
    owner_only_dir(&symlink_data);
    owner_only_dir(&symlink_data.join("protected-content/media-provider"));
    std::os::unix::fs::symlink(&config_path, media_config_path(&symlink_data)).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&symlink_data).is_err());

    let race_path = temp.path().join("race-config");
    fs::write(&race_path, b"preserved-race-winner").unwrap();
    assert!(super::create_private_file_atomically(&race_path, b"loser", 0o600, "config").is_err());
    assert_eq!(fs::read(race_path).unwrap(), b"preserved-race-winner");
}

#[cfg(unix)]
#[test]
fn media_prerequisite_conflict_cleans_only_files_created_by_that_attempt() {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().join("data");
    let source = temp.path().join("source");
    owner_only_dir(&source);
    write_media_prerequisite(&source.join("ffmpeg"), b"ffmpeg-source", 0o700);
    write_media_prerequisite(&source.join("ffprobe"), b"ffprobe-source", 0o700);
    let tools = data_dir.join("protected-content/media-provider/tools");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    owner_only_dir(&data_dir.join("protected-content/media-provider"));
    owner_only_dir(&tools);
    write_media_prerequisite(&tools.join("ffprobe"), b"preserved-conflict", 0o500);

    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
            .unwrap_err();

    assert!(error.to_string().contains("ffprobe import conflicts"));
    assert_eq!(
        fs::read(tools.join("ffprobe")).unwrap(),
        b"preserved-conflict"
    );
    assert!(!tools.join("ffmpeg").exists());
    assert!(!media_config_path(&data_dir).exists());
}

#[cfg(unix)]
fn test_chain_provider_config() -> Value {
    json!({
        "schema": PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1,
        "protected_content_network": {
            "id": "esc-mainnet",
            "rpc_url": "https://private-primary.example.invalid"
        }
    })
}

#[cfg(unix)]
fn canonical_b64<T: CanonicalContract>(value: &T) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.canonical_bytes().unwrap())
}

#[cfg(unix)]
fn raw_b64_32(bytes: [u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(unix)]
fn peer_did_for_seed(seed: u8) -> String {
    crate::crypto::encode_signing_key_did(&SigningKey::from_bytes(&[seed; 32]))
}

#[cfg(unix)]
fn custody_composition_config(
    now: u64,
    routes: Vec<RuntimeCustodyRouteBindingConfig>,
) -> RuntimeCustodyCompositionConfigFile {
    let epoch = signed_custody_epoch();
    let pool = signed_custody_pool_for_epoch(&epoch, (now.saturating_sub(60), now + 3600));
    let authorization =
        signed_committee_authorization_for_epoch(pool.pool_identity().unwrap(), &epoch);
    RuntimeCustodyCompositionConfigFile {
        schema: CUSTODY_COMPOSITION_SCHEMA_V1.to_string(),
        expected_policy_authority_base64: raw_b64_32(
            SigningKey::from_bytes(&[0x71; 32])
                .verifying_key()
                .to_bytes(),
        ),
        expected_committee_authorization_identity_base64: canonical_b64(
            &authorization.authorization_identity().unwrap(),
        ),
        signed_pool_base64: canonical_b64(&pool),
        signed_epoch_base64: canonical_b64(&epoch),
        signed_committee_authorization_base64: canonical_b64(&authorization),
        routes,
    }
}

#[cfg(unix)]
fn custody_route_bindings(
    epoch: &SignedCustodyEpochV1,
    transports: [RuntimeCustodyRouteTransportConfig; 3],
) -> Vec<RuntimeCustodyRouteBindingConfig> {
    epoch
        .statement()
        .nodes()
        .iter()
        .zip(transports)
        .enumerate()
        .map(
            |(index, (node, transport))| RuntimeCustodyRouteBindingConfig {
                node_public_key_base64: raw_b64_32(*node.node_public_key().as_bytes()),
                owner_state_root_base64: raw_b64_32([0x40 + u8::try_from(index).unwrap(); 32]),
                transport,
            },
        )
        .collect()
}

#[cfg(unix)]
fn write_owner_only_custody_composition_config(
    data_dir: &Path,
    config: &RuntimeCustodyCompositionConfigFile,
) {
    let root = protected_content_root(data_dir);
    owner_only_dir(&root);
    let path = custody_composition_config_path(data_dir);
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::to_value(config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
fn assert_runtime_custody_transports(
    composition: &RuntimeCustodyComposition,
    expected: &[ProviderInvocationTransport],
) {
    assert_eq!(composition.nodes.len(), expected.len());
    for (node, expected_transport) in composition.nodes.iter().zip(expected.iter()) {
        assert_eq!(&node.adapter.transport, expected_transport);
    }
    for window in composition.nodes.windows(2) {
        assert!(Arc::ptr_eq(
            &window[0].adapter.registry,
            &window[1].adapter.registry
        ));
    }
}

#[cfg(unix)]
pub(crate) fn mint_draft_for_composition_journal_test() -> RuntimeMintDraft {
    let epoch = signed_custody_epoch();
    let envelope = custody_envelope_for_media_with_epoch(0x41, &epoch);
    let (init_segment, encrypted_segments) = media_components(0x41);
    let mint_nodes = epoch
        .statement()
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let node_seed = u8::try_from(index + 1).unwrap();
            RuntimeMintNodeBinding::new(
                node.node_public_key(),
                CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
                Digest32::new([0x3f + node_seed; 32]),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    RuntimeMintDraft::new(
        &init_segment,
        &encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
        content_access_id(0x41),
        envelope.key_envelope_identity().unwrap(),
        policy_body().policy_identity().unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        mint_nodes,
    )
    .unwrap()
}

#[cfg(unix)]
fn inactive_custody_state_root(data_dir: &Path) -> PathBuf {
    data_dir.join("protected-content/custody-provider/inactive")
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum ProtectedStartupProvider {
    Protect,
    Custody,
    Decrypt,
}

#[cfg(unix)]
impl ProtectedStartupProvider {
    const ALL: [Self; 3] = [Self::Protect, Self::Custody, Self::Decrypt];

    fn name(self) -> &'static str {
        match self {
            Self::Protect => "protect-provider",
            Self::Custody => "custody-provider",
            Self::Decrypt => "protected-content-decrypt-provider",
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::Protect => PROTECT_PROVIDER_ID,
            Self::Custody => CUSTODY_PROVIDER_ID,
            Self::Decrypt => PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
        }
    }

    fn status(self) -> Value {
        match self {
            Self::Protect => json!({
                "status": "ok",
                "data": {
                    "provider": PROTECT_PROVIDER_PROCESS_ID,
                    "version": "0.7.2-alpha.5",
                    "configured": true,
                    "supported_operations": PROTECT_PROVIDER_OPERATIONS,
                    "request_schema": PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                    "response_schema": PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
                }
            }),
            Self::Custody => json!({
                "status": "ok",
                "data": {
                    "provider": CUSTODY_PROVIDER_ID,
                    "version": "0.7.2-alpha.5",
                    "configured": true,
                    "supported_operations": CUSTODY_PROVIDER_OPERATIONS,
                    "request_schema": CUSTODY_PROVIDER_REQUEST_SCHEMA_V1,
                    "response_schema": CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
                }
            }),
            Self::Decrypt => protected_content_decrypt_provider_status(),
        }
    }

    fn prepare_private_config(self, data_dir: &Path) {
        owner_only_dir(data_dir);
        if matches!(self, Self::Custody) {
            owner_only_dir(&inactive_custody_state_root(data_dir));
        }
    }

    async fn register(
        self,
        registry: &Arc<ProviderRegistry>,
        binary: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<()> {
        match self {
            Self::Protect => register_protect_provider(registry, binary).await,
            Self::Custody => {
                // #388 A1: a custody node Home is a WCI-operated host.
                crate::host_trust::seed_for_test(data_dir, true);
                register_custody_provider(registry, binary, data_dir).await
            }
            Self::Decrypt => {
                register_protected_content_decrypt_provider(
                    registry,
                    binary,
                    runtime_operation_issuer_for_seed(0x41),
                )
                .await
            }
        }
    }
}

#[cfg(unix)]
fn write_mock_custody_provider(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    write_mock_custody_provider_with_status(root, &ProtectedStartupProvider::Custody.status())
}

#[cfg(unix)]
fn write_mock_custody_provider_with_status(
    root: &Path,
    status: &Value,
) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join("mock-custody-provider.sh");
    let request_log = root.join("mock-custody-provider.requests");
    let pid_file = root.join("mock-custody-provider.pid");
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"unexpected\"'* ) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"invalid_request\"}}' ;;\n    *'\"op\":\"status\"'*) printf '%s\\n' '{}' ;;\n    *'\"op\":\"release_contribution\"'*) printf '%s\\n' '{{\"status\":\"ok\",\"data\":{{\"echo\":\"custody\"}}}}' ;;\n    *) printf '%s\\n' '{{\"status\":\"ok\",\"data\":{{\"echo\":\"init\"}}}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        status,
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, pid_file, request_log)
}

#[cfg(unix)]
fn write_mock_protected_startup_provider(
    root: &Path,
    provider_name: &str,
    status_response: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    write_mock_protected_startup_provider_with_shutdown(
        root,
        provider_name,
        status_response,
        r#"{"status":"ok"}"#,
    )
}

#[cfg(unix)]
fn write_mock_protected_startup_provider_with_shutdown(
    root: &Path,
    provider_name: &str,
    status_response: &str,
    shutdown_response: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join(format!("mock-{provider_name}.sh"));
    let request_log = root.join(format!("mock-{provider_name}.requests"));
    let pid_file = root.join(format!("mock-{provider_name}.pid"));
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{}'; exit 0 ;;\n    *'\"op\":\"status\"'*) printf '%s\\n' '{}' ;;\n    *'\"op\":\"init\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}' ;;\n    *) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"unexpected\"}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        shutdown_response,
        status_response,
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, pid_file, request_log)
}

#[cfg(unix)]
fn create_test_fifo(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

#[cfg(unix)]
fn write_blocking_protected_status_provider(
    root: &Path,
    provider: ProtectedStartupProvider,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let binary = root.join(format!("mock-{}-timeout.sh", provider.name()));
    let request_log = root.join(format!("mock-{}-timeout.requests", provider.name()));
    let pid_file = root.join(format!("mock-{}-timeout.pid", provider.name()));
    let status_signal = root.join(format!("mock-{}-status.signal", provider.name()));
    let status_release = root.join(format!("mock-{}-status.release", provider.name()));
    create_test_fifo(&status_signal);
    create_test_fifo(&status_release);
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"op\":\"status\"'*) printf x > '{}'; cat '{}' >/dev/null; printf '%s\\n' '{}' ;;\n    *'\"op\":\"init\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}' ;;\n    *) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"unexpected\"}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        status_signal.display(),
        status_release.display(),
        provider.status(),
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, pid_file, request_log, status_signal, status_release)
}

#[cfg(unix)]
fn status_with_field(provider: ProtectedStartupProvider, field: &str, value: Value) -> Value {
    let mut status = provider.status();
    status["data"][field] = value;
    status
}

#[cfg(unix)]
fn protected_startup_status_mismatches(
    provider: ProtectedStartupProvider,
) -> Vec<(&'static str, Value)> {
    let mut extra_operations = provider.status()["data"]["supported_operations"]
        .as_array()
        .unwrap()
        .clone();
    extra_operations.push(json!("unexpected"));
    let mut reordered_operations = provider.status()["data"]["supported_operations"]
        .as_array()
        .unwrap()
        .clone();
    reordered_operations.swap(0, 1);
    let mut extra_data = provider.status();
    extra_data["data"]["route"] = json!("private");
    let mut extra_top = provider.status();
    extra_top["route"] = json!("private");
    vec![
        (
            "identity",
            status_with_field(provider, "provider", json!("wrong-provider")),
        ),
        (
            "version",
            status_with_field(provider, "version", json!("wrong-version")),
        ),
        (
            "configured",
            status_with_field(provider, "configured", json!(false)),
        ),
        (
            "request-schema",
            status_with_field(provider, "request_schema", json!("wrong-request-schema")),
        ),
        (
            "response-schema",
            status_with_field(provider, "response_schema", json!("wrong-response-schema")),
        ),
        (
            "operations-missing",
            status_with_field(provider, "supported_operations", json!(["status"])),
        ),
        (
            "operations-extra",
            status_with_field(
                provider,
                "supported_operations",
                Value::Array(extra_operations),
            ),
        ),
        (
            "operations-reordered",
            status_with_field(
                provider,
                "supported_operations",
                Value::Array(reordered_operations),
            ),
        ),
        ("extra-data", extra_data),
        ("extra-top", extra_top),
    ]
}

#[cfg(unix)]
fn protected_content_decrypt_provider_status() -> Value {
    json!({
        "status": "ok",
        "data": {
            "provider": PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            "version": "0.7.2-alpha.5",
            "configured": true,
            "supported_operations": PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS,
            "request_schema": DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
            "response_schema": DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
        }
    })
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
fn write_mock_protected_content_decrypt_provider(
    root: &Path,
    expected_issuer: RuntimeOperationIssuerKeyV1,
    status: &Value,
) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join("mock-protected-content-decrypt-provider.sh");
    let request_log = root.join("mock-protected-content-decrypt-provider.requests");
    let pid_file = root.join("mock-protected-content-decrypt-provider.pid");
    let expected_issuer = format!("0x{}", hex::encode(expected_issuer.as_bytes()));
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"op\":\"init\"'*)\n      case \"$line\" in\n        *'\"trusted_runtime_issuer\":\"{}\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}' ;;\n        *) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"invalid_config\",\"message\":\"wrong issuer\"}}' ;;\n      esac ;;\n    *'\"op\":\"status\"'*) printf '%s\\n' '{}' ;;\n    *) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"unexpected\",\"message\":\"unexpected\"}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        expected_issuer,
        status,
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, pid_file, request_log)
}

#[cfg(unix)]
fn read_pid(path: &Path) -> u32 {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .last()
        .unwrap()
        .trim()
        .parse()
        .unwrap()
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
async fn protected_provider_startup_timeout_sends_shutdown_and_reaps_child() {
    for provider in ProtectedStartupProvider::ALL {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        provider.prepare_private_config(&data_dir);
        let (binary, pid_file, request_log, status_signal, status_release) =
            write_blocking_protected_status_provider(temp.path(), provider);
        let registry = Arc::new(ProviderRegistry::new());
        let task_registry = registry.clone();
        let task_data_dir = data_dir.clone();
        let registration = tokio::spawn(async move {
            provider
                .register(&task_registry, &binary, &task_data_dir)
                .await
        });

        let mut signal = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&status_signal)
            .await
            .unwrap();
        let mut marker = [0u8; 1];
        signal.read_exact(&mut marker).await.unwrap();
        assert_eq!(marker, [b'x']);
        tokio::time::pause();
        let release_status = tokio::spawn(async move {
            let release = tokio::time::timeout(
                PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT + std::time::Duration::from_millis(1),
                std::future::pending::<()>(),
            )
            .await;
            assert!(release.is_err());
            let mut release = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&status_release)
                .await
                .unwrap();
            release.write_all(b"x").await.unwrap();
        });
        tokio::task::yield_now().await;
        tokio::time::advance(
            PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT + std::time::Duration::from_millis(1),
        )
        .await;
        tokio::time::resume();
        release_status.await.unwrap();

        let error = registration.await.unwrap().unwrap_err();
        assert!(
            error.to_string().contains("status timed out"),
            "{provider:?}: {error}"
        );
        let requests = fs::read_to_string(request_log).unwrap();
        assert!(
            !process_is_running(read_pid(&pid_file)),
            "{provider:?}: {error}; requests={requests}"
        );
        assert!(requests.contains(r#""op":"status""#), "{provider:?}");
        assert!(requests.contains(r#""op":"shutdown""#), "{provider:?}");
        assert!(
            !registry
                .has_ready_runtime_provider_target(provider.target())
                .await
        );
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
fn runtime_custody_composition_loads_valid_owner_only_config_with_local_and_carrier_routes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let peer_did_1 = peer_did_for_seed(0xa1);
    let peer_did_2 = peer_did_for_seed(0xa2);
    let config = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_1.clone(),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_2.clone(),
                },
            ],
        ),
    );
    write_owner_only_custody_composition_config(&data_dir, &config);

    let config_text =
        String::from_utf8(fs::read(custody_composition_config_path(&data_dir)).unwrap()).unwrap();
    assert!(config_text.contains(&peer_did_1));
    assert!(config_text.contains(&peer_did_2));
    assert!(config_text.contains(&config.signed_pool_base64));

    let loaded = load_runtime_custody_composition_config(&data_dir)
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.expected_policy_authority,
        signed_custody_epoch().statement().issuer()
    );
    assert_eq!(
        loaded.signed_pool.canonical_bytes().unwrap(),
        base64::engine::general_purpose::STANDARD
            .decode(&config.signed_pool_base64)
            .unwrap()
    );
    assert!(matches!(
        loaded.routes[0].transport,
        ProviderInvocationTransport::Local
    ));
    assert!(matches!(
        &loaded.routes[1].transport,
        ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
            peer_did,
            timeout_ms: None,
            reply_wait_ms: None,
        }) if peer_did == &peer_did_1
    ));
    assert!(matches!(
        &loaded.routes[2].transport,
        ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
            peer_did,
            timeout_ms: None,
            reply_wait_ms: None,
        }) if peer_did == &peer_did_2
    ));

    let registry = Arc::new(ProviderRegistry::new());
    let composition = load_runtime_custody_composition(&data_dir, registry)
        .unwrap()
        .unwrap();
    assert_runtime_custody_transports(
        &composition,
        &[
            ProviderInvocationTransport::Local,
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peer_did_1.clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peer_did_2.clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
        ],
    );
    let configured = composition.configured_nodes().unwrap();
    assert_eq!(
        resolve_runtime_mint_selected_nodes(
            composition.expected_policy_authority,
            composition.expected_authorization_identity,
            &composition.signed_pool,
            &composition.signed_epoch,
            &composition.signed_committee_authorization,
            now,
            &configured,
        )
        .unwrap()
        .len(),
        3
    );
    assert!(!std::ptr::eq(
        &composition.nodes[0].adapter,
        &composition.nodes[1].adapter
    ));

    let debug = format!("{composition:?}");
    assert!(!debug.contains(&peer_did_1));
    assert!(!debug.contains(&peer_did_2));
    assert!(!debug.contains(&config.signed_pool_base64));
    assert!(!debug.contains(&config.signed_epoch_base64));
    assert!(!debug.contains(&config.signed_committee_authorization_base64));
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_accepts_three_remote_routes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let peers = [
        peer_did_for_seed(0xb1),
        peer_did_for_seed(0xb2),
        peer_did_for_seed(0xb3),
    ];
    let config = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peers[0].clone(),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peers[1].clone(),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peers[2].clone(),
                },
            ],
        ),
    );
    write_owner_only_custody_composition_config(&data_dir, &config);

    let loaded = load_runtime_custody_composition_config(&data_dir)
        .unwrap()
        .unwrap();
    for (route, peer_did) in loaded.routes.iter().zip(peers.iter()) {
        assert!(matches!(
            &route.transport,
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: actual,
                timeout_ms: None,
                reply_wait_ms: None,
            }) if actual == peer_did
        ));
    }

    let composition =
        load_runtime_custody_composition(&data_dir, Arc::new(ProviderRegistry::new()))
            .unwrap()
            .unwrap();
    assert_runtime_custody_transports(
        &composition,
        &[
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peers[0].clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peers[1].clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peers[2].clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
        ],
    );
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_absent_returns_none_without_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);

    let config = load_runtime_custody_composition_config(&data_dir).unwrap();
    assert!(config.is_none());
    assert!(!protected_content_root(&data_dir).exists());
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_rejects_trust_anchor_and_route_mismatches() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let peer_did_1 = peer_did_for_seed(0xc1);
    let peer_did_2 = peer_did_for_seed(0xc2);
    let base_routes = custody_route_bindings(
        &epoch,
        [
            RuntimeCustodyRouteTransportConfig::Local,
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_1.clone(),
            },
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_2.clone(),
            },
        ],
    );

    let mut wrong_policy = custody_composition_config(now, base_routes.clone());
    wrong_policy.expected_policy_authority_base64 = raw_b64_32(
        SigningKey::from_bytes(&[0x72; 32])
            .verifying_key()
            .to_bytes(),
    );
    write_owner_only_custody_composition_config(&data_dir, &wrong_policy);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected trust-anchor rejection")
        .to_string()
        .contains("trust anchors"));

    let mut wrong_auth = custody_composition_config(now, base_routes.clone());
    wrong_auth.expected_committee_authorization_identity_base64 =
        canonical_b64(&CustodyCommitteeAuthorizationIdentityV1::new(digest(0xfe), 1).unwrap());
    write_owner_only_custody_composition_config(&data_dir, &wrong_auth);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected authorization-identity rejection")
        .to_string()
        .contains("trust anchors"));

    let mut missing_route = custody_composition_config(now, base_routes.clone());
    missing_route.routes.pop();
    write_owner_only_custody_composition_config(&data_dir, &missing_route);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected missing-route rejection")
        .to_string()
        .contains("exactly three selected nodes"));

    let mut extra_route = custody_composition_config(now, base_routes.clone());
    extra_route.routes.push(RuntimeCustodyRouteBindingConfig {
        node_public_key_base64: raw_b64_32(*node_public_key(9).as_bytes()),
        owner_state_root_base64: raw_b64_32([0x99; 32]),
        transport: RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
            peer_did: peer_did_for_seed(0xc9),
        },
    });
    write_owner_only_custody_composition_config(&data_dir, &extra_route);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected extra-route rejection")
        .to_string()
        .contains("exactly three selected nodes"));

    let mut duplicate_route = custody_composition_config(now, base_routes.clone());
    duplicate_route.routes[1].node_public_key_base64 =
        duplicate_route.routes[0].node_public_key_base64.clone();
    write_owner_only_custody_composition_config(&data_dir, &duplicate_route);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected duplicate-node rejection")
        .to_string()
        .contains("duplicated or invalid"));

    let mut duplicate_root = custody_composition_config(now, base_routes.clone());
    duplicate_root.routes[1].owner_state_root_base64 =
        duplicate_root.routes[0].owner_state_root_base64.clone();
    write_owner_only_custody_composition_config(&data_dir, &duplicate_root);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected duplicate-root rejection")
        .to_string()
        .contains("duplicated or invalid"));

    let mut two_local = custody_composition_config(now, base_routes.clone());
    two_local.routes[1].transport = RuntimeCustodyRouteTransportConfig::Local;
    write_owner_only_custody_composition_config(&data_dir, &two_local);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected multi-local rejection")
        .to_string()
        .contains("at most one local"));

    let mut duplicate_peer = custody_composition_config(now, base_routes);
    duplicate_peer.routes[2].transport = RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
        peer_did: peer_did_1,
    };
    write_owner_only_custody_composition_config(&data_dir, &duplicate_peer);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected duplicate-peer rejection")
        .to_string()
        .contains("carrier peer DIDs must be distinct"));

    let mut foreign_node = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xca),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xcb),
                },
            ],
        ),
    );
    foreign_node.routes[2].node_public_key_base64 = raw_b64_32(*node_public_key(9).as_bytes());
    write_owner_only_custody_composition_config(&data_dir, &foreign_node);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected foreign-node rejection")
        .to_string()
        .contains("signed node set"));
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_rejects_noncanonical_json_and_base64_and_bad_peer_did() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let mut config = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xdb),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xdc),
                },
            ],
        ),
    );
    owner_only_dir(&protected_content_root(&data_dir));
    let path = custody_composition_config_path(&data_dir);

    fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected noncanonical-json rejection")
        .to_string()
        .contains("not canonical"));

    write_owner_only_custody_composition_config(&data_dir, &config);
    config.signed_pool_base64.push('\n');
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected base64 rejection")
        .to_string()
        .contains("base64"));

    let mut bad_peer = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: "not-a-did".to_string(),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xdd),
                },
            ],
        ),
    );
    write_owner_only_custody_composition_config(&data_dir, &bad_peer);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected invalid did:key rejection")
        .to_string()
        .contains("did:key"));

    bad_peer.routes[1].transport = RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
        peer_did: format!("{} ", peer_did_for_seed(0xde)),
    };
    write_owner_only_custody_composition_config(&data_dir, &bad_peer);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected noncanonical did:key rejection")
        .to_string()
        .contains("did:key"));
}

#[cfg(unix)]
#[test]
fn protected_content_chain_config_loads_owner_only_file_and_accepts_missing_state() {
    let temp = tempfile::tempdir().unwrap();
    let missing_data_dir = temp.path().join("missing");
    owner_only_dir(&missing_data_dir);
    assert!(
        load_runtime_protected_content_chain_provider_config(&missing_data_dir)
            .unwrap()
            .is_none()
    );

    let data_dir = temp.path().join("configured");
    owner_only_dir(&data_dir);
    let config = test_chain_provider_config();
    write_chain_provider_config(&data_dir, &config);

    let loaded = load_runtime_protected_content_chain_provider_config(&data_dir)
        .unwrap()
        .expect("owner-only Chain config");
    assert_eq!(
        loaded.protected_content_network(),
        &config["protected_content_network"]
    );
    assert!(config.get("protected_content_runtime_issuer").is_none());
}

#[cfg(unix)]
#[test]
fn protected_content_chain_config_rejects_unknown_empty_oversized_or_invalid_content() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);

    let mut unknown = test_chain_provider_config();
    unknown["protected_content_runtime_issuer"] = json!("0xoperator-cannot-set-this");
    write_chain_provider_config(&data_dir, &unknown);
    assert!(load_runtime_protected_content_chain_provider_config(&data_dir).is_err());

    for invalid in [
        Vec::new(),
        b"{".to_vec(),
        serde_json::to_vec(&json!({
            "schema": "wrong-schema",
            "protected_content_network": {}
        }))
        .unwrap(),
        serde_json::to_vec(&json!({
            "schema": PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1,
            "protected_content_network": []
        }))
        .unwrap(),
        vec![b'x'; MAX_CHAIN_PROVIDER_CONFIG_BYTES + 1],
    ] {
        fs::write(chain_provider_config_path(&data_dir), invalid).unwrap();
        fs::set_permissions(
            chain_provider_config_path(&data_dir),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(load_runtime_protected_content_chain_provider_config(&data_dir).is_err());
    }
}

#[cfg(unix)]
#[test]
fn protected_content_chain_config_rejects_unsafe_or_nonregular_paths() {
    let temp = tempfile::tempdir().unwrap();
    let config = test_chain_provider_config();

    let mode_data_dir = temp.path().join("mode");
    owner_only_dir(&mode_data_dir);
    write_chain_provider_config(&mode_data_dir, &config);
    fs::set_permissions(
        chain_provider_config_path(&mode_data_dir),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(load_runtime_protected_content_chain_provider_config(&mode_data_dir).is_err());

    fs::set_permissions(
        chain_provider_config_path(&mode_data_dir),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        protected_content_root(&mode_data_dir),
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    assert!(load_runtime_protected_content_chain_provider_config(&mode_data_dir).is_err());

    let directory_data_dir = temp.path().join("directory");
    owner_only_dir(&directory_data_dir);
    owner_only_dir(&protected_content_root(&directory_data_dir));
    owner_only_dir(&chain_provider_config_path(&directory_data_dir));
    assert!(load_runtime_protected_content_chain_provider_config(&directory_data_dir).is_err());

    let symlink_data_dir = temp.path().join("symlink");
    owner_only_dir(&symlink_data_dir);
    owner_only_dir(&protected_content_root(&symlink_data_dir));
    let symlink_target = temp.path().join("chain-provider-target.json");
    fs::write(&symlink_target, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(
        &symlink_target,
        chain_provider_config_path(&symlink_data_dir),
    )
    .unwrap();
    assert!(load_runtime_protected_content_chain_provider_config(&symlink_data_dir).is_err());

    let symlink_parent_data_dir = temp.path().join("symlink-parent");
    owner_only_dir(&symlink_parent_data_dir);
    let symlink_parent_target = temp.path().join("protected-content-target");
    owner_only_dir(&symlink_parent_target);
    let symlink_parent_config = symlink_parent_target.join("chain-provider.json");
    fs::write(&symlink_parent_config, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&symlink_parent_config, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(
        &symlink_parent_target,
        protected_content_root(&symlink_parent_data_dir),
    )
    .unwrap();
    assert!(
        load_runtime_protected_content_chain_provider_config(&symlink_parent_data_dir).is_err()
    );

    let hard_link_data_dir = temp.path().join("hard-link");
    owner_only_dir(&hard_link_data_dir);
    owner_only_dir(&protected_content_root(&hard_link_data_dir));
    let hard_link_source = temp.path().join("chain-provider-source.json");
    fs::write(&hard_link_source, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&hard_link_source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(
        &hard_link_source,
        chain_provider_config_path(&hard_link_data_dir),
    )
    .unwrap();
    assert!(load_runtime_protected_content_chain_provider_config(&hard_link_data_dir).is_err());
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_rejects_unsafe_or_symlinked_paths() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let config = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xd1),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xd2),
                },
            ],
        ),
    );

    write_owner_only_custody_composition_config(&data_dir, &config);
    fs::set_permissions(
        custody_composition_config_path(&data_dir),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected unsafe-file-mode rejection")
        .to_string()
        .contains("owner-only"));

    write_owner_only_custody_composition_config(&data_dir, &config);
    fs::set_permissions(
        protected_content_root(&data_dir),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected unsafe-parent-mode rejection")
        .to_string()
        .contains("owner-only"));

    write_owner_only_custody_composition_config(&data_dir, &config);
    let symlink_data_dir = temp.path().join("symlink-data");
    owner_only_dir(&symlink_data_dir);
    let symlink_root_target = symlink_data_dir.join("protected-root-target");
    owner_only_dir(&symlink_root_target);
    std::os::unix::fs::symlink(
        &symlink_root_target,
        protected_content_root(&symlink_data_dir),
    )
    .unwrap();
    let symlink_config_path = symlink_root_target.join("custody-composition.json");
    fs::write(
        &symlink_config_path,
        serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&symlink_config_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_runtime_custody_composition_config(&symlink_data_dir)
        .err()
        .expect("expected symlink-parent rejection")
        .to_string()
        .contains("owner-only directory"));

    let symlink_file_data_dir = temp.path().join("symlink-file-data");
    owner_only_dir(&symlink_file_data_dir);
    owner_only_dir(&protected_content_root(&symlink_file_data_dir));
    let real_config_dir = temp.path().join("real-config");
    owner_only_dir(&real_config_dir);
    let real_config_path = real_config_dir.join("custody-composition.json");
    fs::write(
        &real_config_path,
        serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&real_config_path, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(
        &real_config_path,
        custody_composition_config_path(&symlink_file_data_dir),
    )
    .unwrap();
    assert!(
        load_runtime_custody_composition_config(&symlink_file_data_dir)
            .err()
            .expect("expected symlink-file rejection")
            .to_string()
            .contains("unavailable")
    );

    let directory_path_data_dir = temp.path().join("directory-path-data");
    owner_only_dir(&directory_path_data_dir);
    owner_only_dir(&protected_content_root(&directory_path_data_dir));
    std::fs::create_dir(custody_composition_config_path(&directory_path_data_dir)).unwrap();
    fs::set_permissions(
        custody_composition_config_path(&directory_path_data_dir),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(
        load_runtime_custody_composition_config(&directory_path_data_dir)
            .err()
            .expect("expected non-regular-file rejection")
            .to_string()
            .contains("regular file")
    );

    let hard_link_data_dir = temp.path().join("hard-link-data");
    owner_only_dir(&hard_link_data_dir);
    owner_only_dir(&protected_content_root(&hard_link_data_dir));
    let hard_link_source_dir = temp.path().join("hard-link-source");
    owner_only_dir(&hard_link_source_dir);
    let hard_link_source = hard_link_source_dir.join("custody-composition.json");
    fs::write(
        &hard_link_source,
        serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&hard_link_source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(
        &hard_link_source,
        custody_composition_config_path(&hard_link_data_dir),
    )
    .unwrap();
    assert!(load_runtime_custody_composition_config(&hard_link_data_dir)
        .err()
        .expect("expected hard-link rejection")
        .to_string()
        .contains("hard-linked"));
}

/// A self-contained, schema-valid purchase record for exercising the
/// purchase-ledger file-discipline path directly, without standing up the
/// full mint/listing/profile harness that `persist_runtime_custody_purchase_for_mint`
/// requires. `load_runtime_custody_purchase`/`persist_runtime_custody_purchase`
/// only check the record's own schema and principal identity, so this fixture
/// does not need to reference a real listing.
fn sample_purchase_record() -> (String, Digest32, RuntimeCustodyPurchaseRecord) {
    let principal_id = "person:local:ledger-fixture".to_string();
    let mint_id = Digest32::new([0x77; 32]);
    let record = RuntimeCustodyPurchaseRecord {
        schema: RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
        principal_id: principal_id.clone(),
        profile_did: "did:key:z6MkFixture".to_string(),
        mint_id: hex::encode(mint_id.as_bytes()),
        content_id: "content:fixture".to_string(),
        cid: "bafyfixture".to_string(),
        listing_sha256: format!("sha256:{}", hex::encode([0x11; 32])),
        seller_address: "0x1111111111111111111111111111111111111111".to_string(),
        chain_namespace: "eip155".to_string(),
        network: "esc-mainnet".to_string(),
        ledger: "erc721".to_string(),
        token_id: "1".to_string(),
        operative: "buy".to_string(),
        price: "1000000000000000000".to_string(),
        pay_token: "0x0000000000000000000000000000000000000000".to_string(),
        payment_processor: None,
        availability_receipt_digest: format!("sha256:{}", hex::encode([0x22; 32])),
        account_id: "wallet-account-fixture".to_string(),
        address: wallet_address_hex(wallet(7)),
        approval_stage: None,
        acquisition: super::RuntimeCustodyAcquisitionV1::Bought,
        capsule_uri: None,
        acquisition_stage: RuntimeCustodyPurchaseStageRecord {
            stage: "buy".to_string(),
            effect_id: "runtime-effect:11111111111111111111111111111111".to_string(),
            approval_request_id: "wallet-request:11111111111111111111111111111111".to_string(),
            request_sha256: format!("sha256:{}", hex::encode([0x33; 32])),
            chain_namespace: "eip155".to_string(),
            network: "esc-mainnet".to_string(),
            to: "0x2222222222222222222222222222222222222222".to_string(),
            value: "0x1".to_string(),
            data: "0x".to_string(),
        },
        progress: RuntimeCustodyPurchaseProgress::Complete {
            terminal: RuntimeCustodyTerminalPurchaseRecord {
                chain_transaction: format!("0x{}", hex::encode([0xaa; 32])),
                wallet_binding: ValidatedChainOutcomeBindingV1::ManagedSigned {
                    signed_transaction_sha256: format!("sha256:{}", hex::encode([0xab; 32])),
                },
                chain_observation: json!({
                    "schema": "elastos.chain.broadcast_receipt/v1",
                    "network": "esc-mainnet",
                }),
                access_evidence: Some(RuntimeCustodyPurchaseAccessEvidenceRecord {
                    schema: "elastos.chain.protected-content-purchase-access/v1".to_string(),
                    request_id: "purchase-access:fixture".to_string(),
                    network: "esc-mainnet".to_string(),
                    chain_id: 8453,
                    wallet: wallet_address_hex(wallet(7)),
                    content_access_id: Some("content-access:fixture".to_string()),
                    ledger: None,
                    token_id: None,
                    has_access: true,
                    finalized_block_number: 44,
                    finalized_block_hash: format!("0x{}", hex::encode([0xad; 32])),
                    finalized_block_timestamp: 1,
                    observed_at: 1,
                }),
                confirmed_at: 1,
                acquired_at: 1,
            },
        },
        created_at: 1,
        updated_at: 1,
    };
    (principal_id, mint_id, record)
}

fn sample_confirmed_purchase_stage() -> RuntimeCustodyConfirmedPurchaseStage {
    RuntimeCustodyConfirmedPurchaseStage {
        chain_transaction: format!("0x{}", hex::encode([0xaa; 32])),
        wallet_binding: ValidatedChainOutcomeBindingV1::ManagedSigned {
            signed_transaction_sha256: format!("sha256:{}", hex::encode([0xab; 32])),
        },
        chain_observation: json!({
            "schema": "elastos.chain.broadcast_receipt/v1",
            "network": "esc-mainnet",
        }),
        confirmed_at: 1,
    }
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

/// A granted copy is recorded only where no record exists, decided under
/// the purchase lock: a purchase under way -- or any record -- that lands
/// first is never overwritten.
#[test]
fn create_runtime_custody_purchase_if_absent_never_overwrites_a_record() {
    let dir = tempfile::tempdir().unwrap();
    owner_only_dir(dir.path());
    let (principal, mint_id, pending) = sample_purchase_record();
    assert!(super::create_runtime_custody_purchase_if_absent(dir.path(), &pending).unwrap());
    let mut granted = pending.clone();
    granted.acquisition = super::RuntimeCustodyAcquisitionV1::Granted;
    granted.account_id = "wallet-account-granted".to_string();
    assert!(!super::create_runtime_custody_purchase_if_absent(dir.path(), &granted).unwrap());
    assert_eq!(
        load_runtime_custody_purchase(dir.path(), &principal, mint_id)
            .unwrap()
            .unwrap(),
        pending
    );
}

#[test]
fn persist_runtime_custody_purchase_serializes_concurrent_writers() {
    let dir = tempfile::tempdir().unwrap();
    owner_only_dir(dir.path());
    let (principal, mint_id, base_record) = sample_purchase_record();
    // Each thread writes a byte-distinguishable record (not a clone of the
    // same bytes) so the final file can only look intact by virtue of one
    // writer's complete record having won, never by chance identity between
    // writers papering over a torn or interleaved write.
    let account_ids: Vec<String> = (0..8)
        .map(|index| format!("wallet-account-fixture-{index}"))
        .collect();
    let handles: Vec<_> = account_ids
        .iter()
        .cloned()
        .map(|account_id| {
            let dir = dir.path().to_path_buf();
            let mut record = base_record.clone();
            record.account_id = account_id;
            std::thread::spawn(move || persist_runtime_custody_purchase(&dir, &record).unwrap())
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    // The real proof of serialization: no two persist calls for this lock
    // path ever held the critical section at the same time. Content
    // round-tripping alone (checked below) would already pass even with the
    // lock removed, since `fs::rename` is independently atomic per writer.
    assert!(
        !runtime_purchase_lock_test_overlap_detected(&runtime_purchase_lock_path(
            dir.path(),
            &principal
        )),
        "two persist_runtime_custody_purchase calls held the purchase lock concurrently"
    );
    let persisted = load_runtime_custody_purchase(dir.path(), &principal, mint_id)
        .unwrap()
        .expect("a purchase record survives concurrent writers");
    assert!(
        account_ids.contains(&persisted.account_id),
        "persisted record must be exactly one writer's complete record, not a mix"
    );
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

#[cfg(unix)]
#[test]
fn runtime_custody_viewer_record_load_rejects_oversized_serialized_state() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let viewer_path = super::runtime_viewer_path(
        &data_dir,
        "person:local:oversized-viewer-record",
        digest(0x61),
    );
    write_owner_only_bytes(&viewer_path, &vec![b'x'; (64 * 1024) + 1]).unwrap();

    let error = super::load_runtime_custody_viewer_record(
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
    let mut record = super::RuntimeCustodyViewerRecord::from_active_session(
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

    let error = super::persist_runtime_custody_viewer_record(
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

#[cfg(unix)]
#[test]
fn runtime_mint_journal_uses_exact_owner_only_root_and_contains_no_route_or_signed_config() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&protected_content_root(&data_dir));
    let config = custody_composition_config(
        crate::auth::now_ts(),
        custody_route_bindings(
            &signed_custody_epoch(),
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xee),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xef),
                },
            ],
        ),
    );
    write_owner_only_custody_composition_config(&data_dir, &config);
    let loaded = load_runtime_custody_composition_config(&data_dir)
        .unwrap()
        .unwrap();
    let configured_peer_did = match &loaded.routes[1].transport {
        ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
            peer_did, ..
        }) => peer_did.clone(),
        _ => panic!("expected carrier route"),
    };

    let journal = runtime_mint_journal(&data_dir);
    let draft = mint_draft_for_composition_journal_test();
    let persisted = journal.persist_bound(&draft).unwrap();
    assert_eq!(persisted.draft().mint_id(), draft.mint_id());

    let mint_root = protected_content_root(&data_dir).join("runtime-mint");
    assert!(mint_root.is_dir());
    assert_eq!(
        fs::metadata(&mint_root).unwrap().permissions().mode() & 0o777,
        0o700
    );

    assert!(!any_file_contains(
        &mint_root,
        base64::engine::general_purpose::STANDARD
            .decode(&config.signed_pool_base64)
            .unwrap()
            .as_slice()
    ));
    assert!(!any_file_contains(
        &mint_root,
        base64::engine::general_purpose::STANDARD
            .decode(&config.signed_epoch_base64)
            .unwrap()
            .as_slice()
    ));
    assert!(!any_file_contains(
        &mint_root,
        base64::engine::general_purpose::STANDARD
            .decode(&config.signed_committee_authorization_base64)
            .unwrap()
            .as_slice()
    ));
    assert!(!any_file_contains(
        &mint_root,
        configured_peer_did.as_bytes()
    ));
}

#[cfg(unix)]
fn read_pids(path: &Path) -> Vec<u32> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| line.trim().parse().unwrap())
        .collect()
}

#[cfg(unix)]
fn process_is_running(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[tokio::test]
async fn runtime_invokes_custody_target_not_any_capsule_sub_provider() {
    let registry = Arc::new(ProviderRegistry::new());
    let custody = RecordingProvider::new(
        "custody",
        json!({"status": "ok", "data": {"echo": "custody"}}),
    );
    let key = RecordingProvider::new(
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_sub_provider("library", key.clone())
        .await
        .unwrap();
    register_custody_runtime_provider_target(registry.as_ref(), custody.clone())
        .await
        .unwrap();

    let data = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({"op": "release_contribution"}),
    )
    .await
    .unwrap();
    assert_eq!(data["echo"], "custody");

    let custody_requests = custody.requests().await;
    let key_requests = key.requests().await;
    assert_eq!(custody_requests.len(), 1);
    assert!(key_requests.is_empty());
    assert_eq!(
        custody_requests[0]["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        custody_requests[0]["_runtime_invocation"]["target"],
        CUSTODY_PROVIDER_ID
    );
    assert_eq!(
        custody_requests[0]["_runtime_invocation"]["carrier"],
        Value::Null
    );
    assert_eq!(
        custody_requests[0]["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
}

#[tokio::test]
async fn runtime_custody_invoke_fails_closed_on_provider_errors() {
    let registry = Arc::new(ProviderRegistry::new());
    let custody = RecordingProvider::new(
        "custody",
        json!({"status": "error", "code": "invalid_request"}),
    );
    register_custody_runtime_provider_target(registry.as_ref(), custody)
        .await
        .unwrap();
    let err = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({"op": "release_contribution"}),
    )
    .await
    .unwrap_err();
    assert!(err.contains("rejected the request"));
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
async fn custody_target_registration_adds_no_capsule_sub_provider_scheme() {
    let registry = Arc::new(ProviderRegistry::new());
    let custody = RecordingProvider::new(
        "custody",
        json!({"status": "ok", "data": {"echo": "custody"}}),
    );
    let key = RecordingProvider::new(
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_sub_provider("library", key)
        .await
        .unwrap();
    register_custody_runtime_provider_target(&registry, custody)
        .await
        .unwrap();
    let mut schemes = registry.sub_provider_schemes().await;
    schemes.sort();
    assert_eq!(schemes, vec!["library".to_string()]);
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

#[cfg(unix)]
#[tokio::test]
async fn custody_registration_passes_the_root_set_from_disk() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    assert!(registry.sub_provider_schemes().await.is_empty());
    assert!(
        registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );

    let response = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({"op": "release_contribution"}),
    )
    .await
    .unwrap();
    assert_eq!(response["echo"], "custody");

    let mut requests = fs::read_to_string(&request_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    let init: Value = serde_json::from_str(&requests.remove(0)).unwrap();
    assert_eq!(init["op"], "init");
    // Plan B T2.1: the base is the custody-provider folder and `extra`
    // lists the roots found on disk, capped by the node settings.
    assert_eq!(
        init["config"]["base_path"],
        Value::String(state_root.parent().unwrap().to_string_lossy().to_string())
    );
    assert_eq!(init["config"]["allowed_paths"], json!([]));
    assert_eq!(init["config"]["read_only"], false);
    assert_eq!(init["config"]["encryption_key"], "");
    assert_eq!(
        init["config"]["extra"],
        json!({
            "roots": [{"path": "inactive"}],
            "max_roots": crate::custody_release_limits::CUSTODY_NODE_SETTINGS.max_pools,
        })
    );
    let status: Value = serde_json::from_str(&requests.remove(0)).unwrap();
    assert_eq!(status, json!({"op": "status"}));
    let forwarded: Value = serde_json::from_str(&requests.remove(0)).unwrap();
    assert_eq!(forwarded["op"], "release_contribution");
    assert!(forwarded.get("_runtime_invocation").is_none());
    assert!(forwarded.get("_runtime_transfer").is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn custody_wrapper_rejects_public_private_op_and_evidence_injection() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let private_op_error = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "evaluate_rights",
        json!({ "op": "evaluate_rights" }),
    )
    .await
    .unwrap_err();
    assert!(private_op_error.contains("invocation failed"));

    let evidence_error = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({
            "op": "release_contribution",
            "chain_data": {"schema": "forbidden"},
        }),
    )
    .await
    .unwrap_err();
    assert!(evidence_error.contains("invocation failed"));

    let extra_field_error = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({
            "op": "release_contribution",
            "unexpected": true,
        }),
    )
    .await
    .unwrap_err();
    assert!(extra_field_error.contains("rejected the request"));

    let carrier_error = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({
            "op": "release_contribution",
            "carrier": {"ticket": "forbidden"},
        }),
    )
    .await
    .unwrap_err();
    assert!(carrier_error.contains("invocation failed"));

    let requests = fs::read_to_string(&request_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    let init: Value = serde_json::from_str(&requests[0]).unwrap();
    assert_eq!(init["op"], "init");
    let status: Value = serde_json::from_str(&requests[1]).unwrap();
    assert_eq!(status, json!({"op": "status"}));
    let forwarded: Value = serde_json::from_str(&requests[2]).unwrap();
    assert_eq!(forwarded["op"], "release_contribution");
    assert_eq!(forwarded["unexpected"], true);
    assert!(forwarded.get("_runtime_invocation").is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn custody_wrapper_status_surface_matches_public_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let status = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "status",
        json!({
            "op": "status",
        }),
    )
    .await
    .unwrap();

    assert_eq!(status["provider"], "custody");
    assert!(semver::Version::parse(status["version"].as_str().unwrap()).is_ok());
    assert_eq!(status["configured"], Value::Bool(true));
    assert_eq!(
        status["supported_operations"],
        json!([
            "status",
            "provision_node_share",
            "release_contribution",
            "evaluate",
            "release_pool_contribution",
            "sign_pool_statement",
            "provision_pool_node_share"
        ])
    );
    assert!(status["supported_operations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|value| value != "shutdown"
            && value != "prepare_evidence"
            && value != "settle_evidence"));
    assert_eq!(status["request_schema"], CUSTODY_PROVIDER_REQUEST_SCHEMA_V1);
    assert_eq!(
        status["response_schema"],
        CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1
    );
}

#[cfg(unix)]
fn custody_runtime_envelope(op: &str, transport: &str) -> Value {
    let carrier = if transport == "carrier-provider-plane" {
        let endpoint = iroh::SecretKey::from_bytes(&[0x51; 32]).public();
        json!({
            "source_endpoint_did": crate::carrier::public_key_to_did(&endpoint)
                .expect("test endpoint must have a canonical DID"),
        })
    } else {
        Value::Null
    };
    json!({
        "schema": "elastos.provider.invocation/v1",
        "source": RUNTIME_PROVIDER_ID,
        "target": CUSTODY_PROVIDER_ID,
        "op": op,
        "capability": format!("provider:{RUNTIME_PROVIDER_ID}->{CUSTODY_PROVIDER_ID}:{op}"),
        "transport": transport,
        "carrier": carrier,
        "transfer": "json",
        "range": Value::Null,
        "progress": Value::Null,
        "abi": {
            "schema": "elastos.provider.transfer-abi/v1",
            "transfer": "json",
            "transport": transport,
            "range_supported": false,
            "progress_supported": false,
            "progress_mode": "none",
            "transport_native_stream": false,
            "backpressure": "not_applicable",
            "cancel_supported": false,
        }
    })
}

#[cfg(unix)]
async fn spawn_custody_wrapper_for_test(binary: &Path, data_dir: &Path) -> InactiveCustodyProvider {
    let state_root = inactive_custody_state_root(data_dir);
    let bridge = ProviderBridge::spawn(
        binary,
        ProviderConfig {
            base_path: state_root.to_str().unwrap().to_owned(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    InactiveCustodyProvider::new(
        Arc::new(bridge),
        Arc::downgrade(&Arc::new(ProviderRegistry::new())),
        // #388 A1: these wrapper tests run as a WCI-operated host.
        true,
        std::env::temp_dir(),
    )
}

#[cfg(unix)]
#[tokio::test]
async fn custody_wrapper_accepts_local_and_carrier_envelopes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let provider = spawn_custody_wrapper_for_test(&binary, &data_dir).await;

    for transport in ["runtime-local-provider-plane", "carrier-provider-plane"] {
        let response = provider
            .send_raw(&json!({
                "op": "release_contribution",
                "_runtime_invocation": custody_runtime_envelope(
                    "release_contribution",
                    transport,
                ),
            }))
            .await
            .unwrap();
        assert_eq!(response["status"], "ok");
    }

    let requests = fs::read_to_string(&request_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    for forwarded in requests.iter().skip(1) {
        let forwarded: Value = serde_json::from_str(forwarded).unwrap();
        assert_eq!(forwarded["op"], "release_contribution");
        assert!(forwarded.get("_runtime_invocation").is_none());
        assert!(forwarded.get("carrier").is_none());
        assert!(!forwarded.to_string().contains("source_endpoint_did"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn custody_wrapper_rejects_invalid_transport_and_injected_carrier_data() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let provider = spawn_custody_wrapper_for_test(&binary, &data_dir).await;

    let invalid_transport = provider
        .send_raw(&json!({
            "op": "release_contribution",
            "_runtime_invocation": custody_runtime_envelope(
                "release_contribution",
                "unsupported-provider-plane",
            ),
        }))
        .await
        .unwrap_err();
    assert!(invalid_transport
        .to_string()
        .contains("runtime envelope is invalid"));

    let injected_carrier = provider
        .send_raw(&json!({
            "op": "release_contribution",
            "_runtime_invocation": custody_runtime_envelope(
                "release_contribution",
                "carrier-provider-plane",
            ),
            "carrier": {"ticket": "forbidden"},
        }))
        .await
        .unwrap_err();
    assert!(injected_carrier
        .to_string()
        .contains("unsupported injected carrier data"));

    for (name, transport, carrier) in [
        (
            "missing authenticated Carrier endpoint",
            "carrier-provider-plane",
            Value::Null,
        ),
        (
            "invalid Carrier endpoint DID",
            "carrier-provider-plane",
            json!({"source_endpoint_did": "did:key:invalid"}),
        ),
        (
            "extra Carrier metadata",
            "carrier-provider-plane",
            json!({
                "source_endpoint_did": crate::carrier::public_key_to_did(
                    &iroh::SecretKey::from_bytes(&[0x52; 32]).public(),
                )
                .unwrap(),
                "route": "forbidden",
            }),
        ),
        (
            "Carrier metadata on a local request",
            "runtime-local-provider-plane",
            json!({
                "source_endpoint_did": crate::carrier::public_key_to_did(
                    &iroh::SecretKey::from_bytes(&[0x53; 32]).public(),
                )
                .unwrap(),
            }),
        ),
    ] {
        let mut envelope = custody_runtime_envelope("release_contribution", transport);
        envelope["carrier"] = carrier;
        let error = provider
            .send_raw(&json!({
                "op": "release_contribution",
                "_runtime_invocation": envelope,
            }))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("runtime envelope is invalid"),
            "{name}: {error}"
        );
    }
}

// Plan B T1.7 (L10, L15): the custody wrapper admits ops from the custody
// surface and rate-limits releases in two stages.

#[cfg(unix)]
fn write_scripted_custody_provider(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join("scripted-custody-provider.sh");
    let request_log = root.join("scripted-custody-provider.requests");
    let prepare_refusal = root.join("scripted-custody-provider.prepare-refusal");
    // `prepare_evidence` is refused with the code written in the refusal
    // file while it exists, and accepted otherwise.
    let script = r#"#!/bin/sh
set -eu
while IFS= read -r line; do
  printf '%s\n' "$line" >> '@LOG@'
  case "$line" in
    *'"op":"shutdown"'*) printf '%s\n' '{"status":"ok"}'; exit 0 ;;
    *'"op":"status"'*) printf '%s\n' '@STATUS@' ;;
    *'"op":"prepare_evidence"'*)
      if [ -e '@REFUSAL@' ]; then
        printf '{"status":"error","code":"%s","message":"refused"}\n' "$(cat '@REFUSAL@')"
      else
        printf '%s\n' '{"status":"ok","data":{"op":"@CHAIN_OP@"}}'
      fi ;;
    *'"op":"settle_evidence"'*) printf '%s\n' '{"status":"ok","data":{"settled":true}}' ;;
    *) printf '%s\n' '{"status":"ok","data":{"echo":"custody"}}' ;;
  esac
done
"#
    .replace("@LOG@", &request_log.display().to_string())
    .replace("@REFUSAL@", &prepare_refusal.display().to_string())
    .replace("@CHAIN_OP@", CHAIN_RIGHTS_EVIDENCE_OP)
    .replace(
        "@STATUS@",
        &ProtectedStartupProvider::Custody.status().to_string(),
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, request_log, prepare_refusal)
}

#[cfg(unix)]
struct ScriptedCustodyWrapper {
    _temp: tempfile::TempDir,
    _registry: Arc<ProviderRegistry>,
    provider: InactiveCustodyProvider,
    chain: Arc<RecordingProvider>,
    request_log: PathBuf,
    prepare_refusal: PathBuf,
}

#[cfg(unix)]
impl ScriptedCustodyWrapper {
    /// A wrapper over the scripted capsule, with a counting fake chain
    /// provider in a registry that stays alive for the test.
    async fn start() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        owner_only_dir(&data_dir);
        let state_root = inactive_custody_state_root(&data_dir);
        owner_only_dir(&state_root);
        let (binary, request_log, prepare_refusal) = write_scripted_custody_provider(temp.path());
        let registry = Arc::new(ProviderRegistry::new());
        let chain = RecordingProvider::new(
            CHAIN_PROVIDER_ID,
            ok_provider_response(json!({"evidence": "fake"})),
        );
        registry
            .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
            .await
            .unwrap();
        let bridge = ProviderBridge::spawn(
            &binary,
            ProviderConfig {
                base_path: state_root.to_str().unwrap().to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let provider = InactiveCustodyProvider::new(
            Arc::new(bridge),
            Arc::downgrade(&registry),
            true,
            temp.path().to_path_buf(),
        );
        Self {
            _temp: temp,
            _registry: registry,
            provider,
            chain,
            request_log,
            prepare_refusal,
        }
    }

    fn refuse_prepare(&self, code: &str) {
        fs::write(&self.prepare_refusal, code).unwrap();
    }

    fn accept_prepare(&self) {
        fs::remove_file(&self.prepare_refusal).unwrap();
    }

    /// The frames the wrapper forwarded to the capsule after start-up.
    fn forwarded(&self) -> Vec<Value> {
        fs::read_to_string(&self.request_log)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|frame| !matches!(frame["op"].as_str(), Some("init" | "status")))
            .collect()
    }

    fn forwarded_count(&self, op: &str) -> usize {
        self.forwarded()
            .iter()
            .filter(|frame| frame["op"] == op)
            .count()
    }

    async fn chain_reads(&self) -> usize {
        self.chain.requests().await.len()
    }

    async fn send(&self, request: Value, envelope: Value) -> Result<Value, ProviderError> {
        let mut request = request;
        request["_runtime_invocation"] = envelope;
        self.provider.send_raw(&request).await
    }
}

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
fn custody_local_envelope(op: &str) -> Value {
    custody_runtime_envelope(op, "runtime-local-provider-plane")
}

#[cfg(unix)]
fn custody_carrier_envelope(op: &str, endpoint_seed: u8) -> Value {
    let mut envelope = custody_runtime_envelope(op, "carrier-provider-plane");
    envelope["carrier"] = json!({
        "source_endpoint_did": crate::carrier::public_key_to_did(
            &iroh::SecretKey::from_bytes(&[endpoint_seed; 32]).public(),
        )
        .unwrap(),
    });
    envelope
}

/// One evaluate request carrying a V2 pool operation from the shared
/// contracts fixture, asking the fixture pool's node 1.
#[cfg(unix)]
fn custody_v2_evaluate_request() -> Value {
    use elastos_protected_content_contracts::test_fixtures::{
        node_public_key as pool_node_public_key, pool_release_fixture, PoolReleaseSpecV1,
    };
    let fixture = pool_release_fixture(&PoolReleaseSpecV1::new(
        xwing_public_key_bytes,
        policy_body(),
        crate::auth::now_ts(),
    ));
    let request = RightsProviderRequestV1::new_evaluate_any(
        pool_node_public_key(1),
        &elastos_protected_content_contracts::RuntimeReleaseOperationAnyV1::V2(fixture.operation),
    )
    .unwrap();
    serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
}

/// One wallet-signed evaluate request (one wallet, one item).
#[cfg(unix)]
fn custody_evaluate_request() -> Value {
    let envelope = custody_envelope_for_media(0x11);
    let operation = make_signed_runtime_release_operation_for_envelope_and_seed(0x21, &envelope);
    let request = RightsProviderRequestV1::new_evaluate(node_public_key(1), &operation).unwrap();
    serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
}

#[cfg(unix)]
fn assert_rate_limited(response: &Value) {
    assert_eq!(response["status"], "error", "{response}");
    assert_eq!(response["code"], "rate_limited", "{response}");
}

#[cfg(unix)]
fn endpoint_budget() -> usize {
    crate::custody_release_limits::CUSTODY_NODE_SETTINGS.releases_per_endpoint_per_minute as usize
}

#[cfg(unix)]
fn wallet_budget() -> usize {
    crate::custody_release_limits::CUSTODY_NODE_SETTINGS.releases_per_wallet_per_minute as usize
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

#[test]
fn custody_ops_are_declared_in_the_surface() {
    use crate::custody_surface::{declared_ops, OP_CUSTODY_EVALUATE, TARGET_CUSTODY};
    let declared: Vec<&str> = declared_ops(TARGET_CUSTODY).collect();
    // Every capsule op but `shutdown` is a declared op of the target, and
    // the target declares only capsule ops and the wrapper's own `evaluate`.
    for op in CUSTODY_PROVIDER_OPERATIONS {
        assert_eq!(declared.contains(op), *op != "shutdown", "{op}");
    }
    for op in &declared {
        assert!(
            *op == OP_CUSTODY_EVALUATE || CUSTODY_PROVIDER_OPERATIONS.contains(op),
            "{op}"
        );
    }
    for code in ["unknown_envelope", "rate_limited"] {
        assert!(
            super::CUSTODY_EFFECT_FREE_REFUSAL_CODES.contains(&code),
            "{code}"
        );
        assert!(
            super::CUSTODY_REPORTABLE_REFUSAL_CODES.contains(&code),
            "{code}"
        );
    }
}

#[tokio::test]
async fn runtime_custody_registry_adapter_invokes_selected_custody_endpoint_for_rights() {
    let registry = Arc::new(ProviderRegistry::new());
    let envelope = custody_envelope_for_media(0x11);
    let operation = make_signed_runtime_release_operation_for_envelope_and_seed(0x21, &envelope);
    let decision = make_signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed);
    let custody = RecordingProvider::new(
        "custody",
        ok_provider_response(
            serde_json::to_value(RightsProviderResponseV1::new_decision(&decision).unwrap())
                .unwrap(),
        ),
    );
    let unrelated = RecordingProvider::new(
        "library",
        ok_provider_response(json!({"echo": "unrelated-capsule-provider"})),
    );
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, custody.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("library", unrelated.clone())
        .await
        .unwrap();

    let adapter = RuntimeCustodyRegistryAdapter::new(
        registry.clone(),
        elastos_runtime::provider::ProviderInvocationTransport::Local,
        super::RuntimeCustodyCallDiagnostics::default(),
    );
    let request = RightsProviderRequestV1::new_evaluate(node_public_key(1), &operation).unwrap();

    let response = adapter.evaluate_rights(&request).await.unwrap();
    assert_eq!(
        response.status(),
        elastos_protected_content_provider_contracts::RightsProviderResponseStatusV1::Decision
    );
    let custody_requests = custody.requests().await;
    assert_eq!(custody_requests.len(), 1);
    assert!(unrelated.requests().await.is_empty());
    let recorded = &custody_requests[0];
    assert_eq!(recorded["op"], "evaluate");
    assert_eq!(
        recorded["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["target"],
        CUSTODY_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert_eq!(recorded["_runtime_invocation"]["carrier"], Value::Null);
    assert!(recorded.get("chain_data").is_none());
    assert!(recorded.get("evidence").is_none());
    let debug = format!("{adapter:?}");
    assert!(!debug.contains("runtime-local-provider-plane"));
    assert!(!debug.contains("ProviderRegistry"));
}

#[tokio::test]
async fn runtime_custody_registry_adapter_invokes_selected_custody_endpoint_for_release() {
    let registry = Arc::new(ProviderRegistry::new());
    let envelope = custody_envelope_for_media(0x11);
    let operation = make_signed_runtime_release_operation_for_envelope_and_seed(0x21, &envelope);
    let decision = make_signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed);
    let contribution = make_signed_node_contribution(&operation, 1);
    let custody = RecordingProvider::new(
        "custody",
        ok_provider_response(
            serde_json::to_value(
                CustodyProviderResponseV1::new_contribution(&contribution).unwrap(),
            )
            .unwrap(),
        ),
    );
    let unrelated = RecordingProvider::new(
        "library",
        ok_provider_response(json!({"echo": "unrelated-capsule-provider"})),
    );
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, custody.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("library", unrelated.clone())
        .await
        .unwrap();

    let adapter = RuntimeCustodyRegistryAdapter::new(
        registry.clone(),
        elastos_runtime::provider::ProviderInvocationTransport::Local,
        super::RuntimeCustodyCallDiagnostics::default(),
    );
    let request =
        CustodyProviderRequestV1::new_release_contribution(&operation, &decision).unwrap();

    let response = adapter.release_contribution(&request).await.unwrap();
    assert_eq!(
        response.status(),
        elastos_protected_content_provider_contracts::CustodyProviderResponseStatusV1::Contribution
    );
    let custody_requests = custody.requests().await;
    assert_eq!(custody_requests.len(), 1);
    assert!(unrelated.requests().await.is_empty());
    let recorded = &custody_requests[0];
    assert_eq!(recorded["op"], "release_contribution");
    assert_eq!(
        recorded["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["target"],
        CUSTODY_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert_eq!(recorded["_runtime_invocation"]["carrier"], Value::Null);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_registry_adapter_process_happy_path_uses_public_provision_receipt() {
    let binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let temp_root = fs::canonicalize(temp.path()).unwrap();
    let data_dir = temp_root.join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(state_root.parent().unwrap());
    let provisioned = provision_custody_node_public_receipt(&binary, &state_root, 0x21);

    let registry = Arc::new(ProviderRegistry::new());
    crate::host_trust::seed_wci_host_for_test(&data_dir);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let custody_epoch = signed_custody_epoch_with_first_node(
        provisioned.node_public_key,
        provisioned.node_custody_public_key,
    );
    let provisioning_now = crate::auth::now_ts();
    let envelope =
        provisioned_custody_envelope_for_media_with_epoch(0x11, &custody_epoch, provisioning_now);
    let provisioning_record =
        provisioning_record_for_selected_node(&envelope, provisioned.node_public_key);
    let provisioning =
        signed_runtime_custody_provisioning_at(&provisioning_record, 0x21, provisioning_now);
    let adapter = RuntimeCustodyRegistryAdapter::new(
        registry.clone(),
        elastos_runtime::provider::ProviderInvocationTransport::Local,
        super::RuntimeCustodyCallDiagnostics::default(),
    );

    let provision_request =
        CustodyProviderRequestV1::new_provision_node_share(&provisioning_record, &provisioning)
            .unwrap();
    let provision_response = adapter
        .provision_node_share(&provision_request)
        .await
        .unwrap();
    assert_eq!(
        provision_response.provisioned_record_identity().unwrap(),
        provisioning_record.record_identity().unwrap()
    );

    let operation_now = crate::auth::now_ts();
    let operation = make_signed_runtime_release_operation_for_envelope_and_epoch_at(
        0x21,
        &envelope,
        custody_epoch.clone(),
        operation_now,
    );
    let rights_request =
        RightsProviderRequestV1::new_evaluate(provisioned.node_public_key, &operation).unwrap();
    let chain = ProcessChainEvidenceProvider::new(rights_request.clone(), true);
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
        .await
        .unwrap();

    let rights_validation_now = crate::auth::now_ts();
    let validated_rights = match ValidatedRightsProviderRequestV1::decode_and_validate_at(
        &rights_request.to_json_vec().unwrap(),
        rights_validation_now,
    ) {
        Ok(validated) => validated,
        Err(error) => panic!("local rights request validation failed: {error:?}"),
    };
    assert_eq!(
        validated_rights.selected_node_public_key(),
        provisioned.node_public_key
    );

    let rights_response = adapter.evaluate_rights(&rights_request).await.unwrap();
    let decision = rights_response.signed_node_rights_decision().unwrap();
    let release_request =
        CustodyProviderRequestV1::new_release_contribution(&operation, &decision).unwrap();
    let release_validation_now = crate::auth::now_ts();
    let validated_release = ValidatedCustodyProviderRequestV1::decode_and_validate_at(
        &release_request.to_json_vec().unwrap(),
        runtime_operation_issuer_for_seed(0x21),
        provisioned.node_public_key,
        release_validation_now,
    )
    .unwrap();
    let validated_release = validated_release.release_contribution().unwrap();
    let authenticated_operation = operation
        .verify(
            operation.statement().runtime_operation_issuer(),
            release_validation_now,
        )
        .unwrap();
    assert_eq!(
        validated_release.authenticated_runtime_release_operation(),
        &authenticated_operation
    );
    assert_eq!(validated_release.signed_node_rights_decision(), &decision);
    let release_response = adapter
        .release_contribution(&release_request)
        .await
        .unwrap();
    if release_response.status()
        == elastos_protected_content_provider_contracts::CustodyProviderResponseStatusV1::Failure
    {
        panic!(
            "release provider failure: {:?}",
            release_response.failure_code().unwrap()
        );
    }
    let contribution = release_response.signed_node_contribution().unwrap();

    let verification_now = crate::auth::now_ts();
    let authenticated = operation
        .verify(
            operation.statement().runtime_operation_issuer(),
            verification_now,
        )
        .unwrap();
    let node_set = custody_epoch.statement().node_set().unwrap();
    authenticated
        .verify_node_contribution(&contribution, &node_set, verification_now)
        .unwrap();

    let chain_requests = chain.requests().await;
    assert_eq!(chain_requests.len(), 1);
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
        chain_requests[0]["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["carrier"],
        Value::Null
    );
    let mut inner_chain_request = chain_requests[0].clone();
    inner_chain_request
        .as_object_mut()
        .unwrap()
        .remove("_runtime_invocation");
    assert_eq!(
        inner_chain_request,
        chain_rights_evidence_request(&operation).unwrap()
    );
}

/// Plan B POOL-MINT (PM-F2): a WCI-operated custody host whose real provider
/// serves its inactive root behind a script that records the provider's pid,
/// so a test can pause the provider after a share write is dispatched.
#[cfg(unix)]
struct HostShareWriteFixture {
    _temp: tempfile::TempDir,
    data_dir: PathBuf,
    provider: Arc<InactiveCustodyProvider>,
    pid_file: PathBuf,
    node_public_key: NodePublicKey,
    custody_epoch: SignedCustodyEpochV1,
}

#[cfg(unix)]
impl HostShareWriteFixture {
    async fn start(max_storage_bytes: Option<u64>) -> Self {
        let binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
        let temp = tempfile::tempdir().unwrap();
        let temp_root = fs::canonicalize(temp.path()).unwrap();
        let data_dir = temp_root.join("data");
        owner_only_dir(&data_dir);
        crate::host_trust::write_host_trust(
            &data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            max_storage_bytes,
        )
        .unwrap();
        let state_root = inactive_custody_state_root(&data_dir);
        owner_only_dir(state_root.parent().unwrap());
        let provisioned = provision_custody_node_public_receipt(&binary, &state_root, 0x21);
        let wrapper = temp_root.join("custody-provider.sh");
        let pid_file = temp_root.join("custody-provider.pid");
        crate::test_support::write_from_child(
            &wrapper,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{}'\nexec '{}' \"$@\"\n",
                pid_file.display(),
                binary.display(),
            ),
            0o700,
        );
        let bridge = ProviderBridge::spawn(
            &wrapper,
            super::custody_provider_roots_config(&data_dir).unwrap(),
        )
        .await
        .unwrap();
        let provider = Arc::new(InactiveCustodyProvider::new(
            Arc::new(bridge),
            Arc::downgrade(&Arc::new(ProviderRegistry::new())),
            true,
            data_dir.clone(),
        ));
        Self {
            _temp: temp,
            data_dir,
            provider,
            pid_file,
            node_public_key: provisioned.node_public_key,
            custody_epoch: signed_custody_epoch_with_first_node(
                provisioned.node_public_key,
                provisioned.node_custody_public_key,
            ),
        }
    }

    fn set_storage_maximum(&self, max_storage_bytes: Option<u64>) {
        crate::host_trust::write_host_trust(
            &self.data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            max_storage_bytes,
        )
        .unwrap();
    }

    /// A Runtime-local V1 share write for the media of `seed`.
    fn v1_share_request(&self, seed: u8) -> Value {
        let now = crate::auth::now_ts();
        let envelope =
            provisioned_custody_envelope_for_media_with_epoch(seed, &self.custody_epoch, now);
        let record = provisioning_record_for_selected_node(&envelope, self.node_public_key);
        let provisioning = signed_runtime_custody_provisioning_at(&record, 0x21, now);
        let mut request: Value = serde_json::from_slice(
            &CustodyProviderRequestV1::new_provision_node_share(&record, &provisioning)
                .unwrap()
                .to_json_vec()
                .unwrap(),
        )
        .unwrap();
        request["_runtime_invocation"] =
            custody_runtime_envelope("provision_node_share", "runtime-local-provider-plane");
        request
    }

    /// What the wrapper charges a write: its frame without the envelope.
    fn charged_bytes(request: &Value) -> u64 {
        let mut frame = request.clone();
        frame.as_object_mut().unwrap().remove("_runtime_invocation");
        u64::try_from(serde_json::to_vec(&frame).unwrap().len()).unwrap()
    }

    fn used_bytes(&self) -> u64 {
        super::host_custody_storage_bytes(&self.data_dir).unwrap()
    }

    fn signal_provider(&self, signal: nix::sys::signal::Signal) {
        let pid: i32 = fs::read_to_string(&self.pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal).unwrap();
    }
}

/// PM-F2 (a): the host-wide share lock belongs to the write, not to its
/// caller. A caller cancelled after its write was dispatched leaves the lock
/// held until that write has landed, so the next write waits for it and is
/// checked against its bytes: two writes that each fit the maximum alone,
/// not together, never both commit.
#[cfg(unix)]
#[tokio::test]
async fn guard_a_share_write_cancelled_after_dispatch_keeps_the_host_lock_until_it_lands() {
    let host = HostShareWriteFixture::start(None).await;
    let first = host.v1_share_request(0x11);
    let second = host.v1_share_request(0x12);
    let max = HostShareWriteFixture::charged_bytes(&first)
        .max(HostShareWriteFixture::charged_bytes(&second));
    host.set_storage_maximum(Some(max));

    // The paused provider leaves the dispatched write unanswered.
    host.signal_provider(nix::sys::signal::Signal::SIGSTOP);
    let provider = host.provider.clone();
    let cancelled = tokio::spawn(async move { provider.send_raw(&first).await });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    let provider = host.provider.clone();
    let next = tokio::spawn(async move { provider.send_raw(&second).await });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    host.signal_provider(nix::sys::signal::Signal::SIGCONT);

    let answer = next.await.unwrap().unwrap();
    assert_eq!(
        answer["code"],
        crate::host_trust::HOST_STORAGE_FULL,
        "{answer}"
    );
    // The cancelled write landed, and it alone.
    let used = host.used_bytes();
    assert!(used > 0 && used <= max, "used {used} of {max}");
    let store = elastos_protected_content_custody::NodeLocalShareStoreV1::new(
        host.node_public_key,
        custody_provider::node_share_store_dir(&super::custody_root_dir(
            &host.data_dir,
            custody_provider::CUSTODY_INACTIVE_ROOT_PATH,
        )),
    );
    assert_eq!(store.count().unwrap(), 1);
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

#[cfg(unix)]
#[tokio::test]
async fn runtime_release_coordinator_process_two_of_three_success_stops_before_third_node() {
    let binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let temp_root = fs::canonicalize(temp.path()).unwrap();

    let node1 = provisioned_process_custody_node(&binary, &temp_root, "node-1", 0x21, digest(0xa1));
    let node2 = provisioned_process_custody_node(&binary, &temp_root, "node-2", 0x21, digest(0xa2));
    let node3 = provisioned_process_custody_node(&binary, &temp_root, "node-3", 0x21, digest(0xa3));

    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-1"));
    register_custody_provider(&node1.registry, &binary, &temp_root.join("node-1"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-2"));
    register_custody_provider(&node2.registry, &binary, &temp_root.join("node-2"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-3"));
    register_custody_provider(&node3.registry, &binary, &temp_root.join("node-3"))
        .await
        .unwrap();

    let custody_epoch = signed_custody_epoch_for_node_keys([
        (
            node1.provisioned.node_public_key,
            node1.provisioned.node_custody_public_key,
        ),
        (
            node2.provisioned.node_public_key,
            node2.provisioned.node_custody_public_key,
        ),
        (
            node3.provisioned.node_public_key,
            node3.provisioned.node_custody_public_key,
        ),
    ]);
    let fixtures_by_node = BTreeMap::from([
        (node1.provisioned.node_public_key, node1),
        (node2.provisioned.node_public_key, node2),
        (node3.provisioned.node_public_key, node3),
    ]);
    let ordered_node_keys = custody_epoch
        .statement()
        .nodes()
        .iter()
        .map(|node| node.node_public_key())
        .collect::<Vec<_>>();
    let ordered_fixtures = ordered_node_keys
        .iter()
        .map(|node_public_key| fixtures_by_node.get(node_public_key).unwrap())
        .collect::<Vec<_>>();
    let provisioning_now = crate::auth::now_ts();
    let envelope =
        provisioned_custody_envelope_for_media_with_epoch(0x11, &custody_epoch, provisioning_now);
    for fixture in fixtures_by_node.values() {
        provision_selected_node_share(fixture, &envelope, 0x21, provisioning_now).await;
    }

    let operation_now = crate::auth::now_ts();
    let operation = make_signed_runtime_release_operation_for_envelope_and_epoch_at(
        0x21,
        &envelope,
        custody_epoch.clone(),
        operation_now,
    );
    let rights_request_1 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[0].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let rights_request_2 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[1].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let rights_request_3 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[2].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let chain1 = ProcessChainEvidenceProvider::new(rights_request_1, true);
    let chain2 = ProcessChainEvidenceProvider::new(rights_request_2, true);
    let chain3 = ProcessChainEvidenceProvider::new(rights_request_3, true);
    ordered_fixtures[0]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain1.clone())
        .await
        .unwrap();
    ordered_fixtures[1]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain2.clone())
        .await
        .unwrap();
    ordered_fixtures[2]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain3.clone())
        .await
        .unwrap();

    let runtime_owner_parent = temp_root.join("runtime-owner-only-parent");
    owner_only_dir(&runtime_owner_parent);
    let runtime_data_dir = runtime_owner_parent.join("runtime-release");
    let coordinator = RuntimeReleaseCoordinator::new(
        RuntimeReleaseJournal::new(runtime_data_dir.clone()),
        runtime_operation_issuer_for_seed(0x21),
        vec![
            RuntimeSelectedProvider::new(
                ordered_fixtures[0].provisioned.node_public_key,
                &ordered_fixtures[0].adapter,
                &ordered_fixtures[0].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[1].provisioned.node_public_key,
                &ordered_fixtures[1].adapter,
                &ordered_fixtures[1].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[2].provisioned.node_public_key,
                &ordered_fixtures[2].adapter,
                &ordered_fixtures[2].adapter,
            ),
        ],
    )
    .unwrap()
    .with_response_clock(crate::auth::now_ts);
    let wallet_now = crate::auth::now_ts();
    let (wallet_request, wallet_response) = wallet_request_response_for_release_at(
        &operation,
        "profile:alpha",
        "wallet-account-alpha",
        "wallet-request:11111111111111111111111111111111",
        wallet_now,
    );

    let outcome = coordinator
        .release(
            &wallet_request,
            &wallet_response,
            operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    let signed_node_contributions = match outcome {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::ContributionsReady {
                signed_node_contributions,
            },
        ) => signed_node_contributions,
        other => panic!("unexpected coordinator outcome: {other:?}"),
    };
    assert_eq!(signed_node_contributions.len(), 2);
    let verification_now = crate::auth::now_ts();
    let authenticated = operation
        .verify(
            operation.statement().runtime_operation_issuer(),
            verification_now,
        )
        .unwrap();
    let node_set = custody_epoch.statement().node_set().unwrap();
    for contribution in &signed_node_contributions {
        authenticated
            .verify_node_contribution(contribution, &node_set, verification_now)
            .unwrap();
    }
    let contributing_nodes: Vec<_> = signed_node_contributions
        .iter()
        .map(|contribution| {
            contribution
                .statement()
                .signed_rights_decision()
                .statement()
                .node_public_key()
        })
        .collect();
    assert_eq!(
        contributing_nodes,
        vec![
            ordered_fixtures[0].provisioned.node_public_key,
            ordered_fixtures[1].provisioned.node_public_key,
        ]
    );
    assert_eq!(chain1.requests().await.len(), 1);
    assert_eq!(chain2.requests().await.len(), 1);
    assert_eq!(chain3.requests().await.len(), 0);
    assert!(list_unresolved_runtime_releases(&runtime_data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&runtime_data_dir)
        .unwrap()
        .is_empty());
    let terminal_debug = format!(
        "{:?}",
        RuntimeReleaseTerminalResult::ContributionsReady {
            signed_node_contributions,
        }
    );
    assert!(!terminal_debug.contains("node-1"));
    assert!(!terminal_debug.contains("node-2"));
    assert!(!terminal_debug.contains("node-3"));
    assert!(!terminal_debug.contains("carrier-provider-plane"));

    ordered_fixtures[0]
        .registry
        .unregister_sub_provider(CHAIN_PROVIDER_ID)
        .await
        .unwrap();
    ordered_fixtures[1]
        .registry
        .unregister_sub_provider(CHAIN_PROVIDER_ID)
        .await
        .unwrap();
    ordered_fixtures[2]
        .registry
        .unregister_sub_provider(CHAIN_PROVIDER_ID)
        .await
        .unwrap();

    let beta_now = crate::auth::now_ts();
    let beta_operation =
        make_signed_runtime_release_operation_for_envelope_and_epoch_and_recipient_at(
            0x21,
            &envelope,
            custody_epoch.clone(),
            recipient_public_key(0x31),
            recipient_identity(0x31),
            RuntimeReleaseAuditIdV1::new(digest(0xb2)).unwrap(),
            beta_now,
        );
    let (beta_wallet_request, beta_wallet_response) =
        wallet_request_response_for_release_context_at(
            &beta_operation,
            "profile:beta",
            "runtime-session:beta",
            Some("proof:beta"),
            "grant:beta",
            "launch:beta",
            "wallet-account-beta",
            "wallet-request:22222222222222222222222222222222",
            beta_now,
        );
    let beta_rights_request_1 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[0].provisioned.node_public_key,
        &beta_operation,
    )
    .unwrap();
    let beta_rights_request_2 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[1].provisioned.node_public_key,
        &beta_operation,
    )
    .unwrap();
    let beta_rights_request_3 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[2].provisioned.node_public_key,
        &beta_operation,
    )
    .unwrap();
    let beta_chain1 = ProcessChainEvidenceProvider::new(beta_rights_request_1, false);
    let beta_chain2 = ProcessChainEvidenceProvider::new(beta_rights_request_2, false);
    let beta_chain3 = ProcessChainEvidenceProvider::new(beta_rights_request_3, false);
    ordered_fixtures[0]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, beta_chain1.clone())
        .await
        .unwrap();
    ordered_fixtures[1]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, beta_chain2.clone())
        .await
        .unwrap();
    ordered_fixtures[2]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, beta_chain3.clone())
        .await
        .unwrap();

    let beta_outcome = coordinator
        .release(
            &beta_wallet_request,
            &beta_wallet_response,
            beta_operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    let beta_denied = match beta_outcome {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::RightsDenied {
                signed_node_rights_decision,
            },
        ) => signed_node_rights_decision,
        other => panic!("unexpected beta coordinator outcome: {other:?}"),
    };
    assert_eq!(beta_denied.statement().decision(), RightsDecisionV1::Denied);
    // The two nodes the threshold needs are asked together, so the denial is
    // whichever of them answered first, and the other may have stopped before
    // its chain read; the third node is never asked.
    assert!([
        ordered_fixtures[0].provisioned.node_public_key,
        ordered_fixtures[1].provisioned.node_public_key,
    ]
    .contains(&beta_denied.statement().node_public_key()));
    let beta_chain_reads = [
        beta_chain1.requests().await.len(),
        beta_chain2.requests().await.len(),
    ];
    assert!(beta_chain_reads.iter().all(|reads| *reads <= 1));
    assert!(beta_chain_reads.iter().sum::<usize>() >= 1);
    assert_eq!(beta_chain3.requests().await.len(), 0);

    let beta_replay = coordinator
        .release(
            &beta_wallet_request,
            &beta_wallet_response,
            beta_operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    let beta_replay_denied = match beta_replay {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::RightsDenied {
                signed_node_rights_decision,
            },
        ) => signed_node_rights_decision,
        other => panic!("unexpected beta replay outcome: {other:?}"),
    };
    assert_eq!(beta_replay_denied, beta_denied);
    assert_eq!(
        [
            beta_chain1.requests().await.len(),
            beta_chain2.requests().await.len(),
        ],
        beta_chain_reads,
        "a replayed denial asks no node again"
    );
    assert_eq!(beta_chain3.requests().await.len(), 0);

    let beta_persisted = RuntimeReleaseJournal::new(runtime_data_dir.clone())
        .load(beta_operation.canonical_hash().unwrap())
        .unwrap();
    assert!(matches!(
        beta_persisted.terminal_result(),
        Some(RuntimeReleaseTerminalResult::RightsDenied { .. })
    ));
    assert_eq!(
        beta_persisted
            .terminal_result()
            .unwrap()
            .contribution_count(),
        0
    );
    assert!(list_unresolved_runtime_releases(&runtime_data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&runtime_data_dir)
        .unwrap()
        .is_empty());
    let beta_terminal_debug = format!(
        "{:?}",
        RuntimeReleaseTerminalResult::RightsDenied {
            signed_node_rights_decision: beta_denied.clone(),
        }
    );
    assert!(!beta_terminal_debug.contains("node-1"));
    assert!(!beta_terminal_debug.contains("node-2"));
    assert!(!beta_terminal_debug.contains("node-3"));
    assert!(!beta_terminal_debug.contains("carrier-provider-plane"));

    for fixture in ordered_fixtures {
        fixture
            .registry
            .unregister_sub_provider(CHAIN_PROVIDER_ID)
            .await
            .unwrap();
        fixture
            .registry
            .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
            .unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_decrypt_registry_adapter_process_reconstructs_for_prepared_recipient_and_closes_cleanly(
) {
    let custody_binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let decrypt_binary = required_test_binary_path(TEST_DECRYPT_PROVIDER_BIN_ENV);
    let protect_binary = required_test_binary_path(TEST_PROTECT_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let temp_root = fs::canonicalize(temp.path()).unwrap();

    let node1 =
        provisioned_process_custody_node(&custody_binary, &temp_root, "node-1", 0x21, digest(0xa1));
    let node2 =
        provisioned_process_custody_node(&custody_binary, &temp_root, "node-2", 0x21, digest(0xa2));
    let node3 =
        provisioned_process_custody_node(&custody_binary, &temp_root, "node-3", 0x21, digest(0xa3));

    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-1"));
    register_custody_provider(&node1.registry, &custody_binary, &temp_root.join("node-1"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-2"));
    register_custody_provider(&node2.registry, &custody_binary, &temp_root.join("node-2"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-3"));
    register_custody_provider(&node3.registry, &custody_binary, &temp_root.join("node-3"))
        .await
        .unwrap();

    let custody_epoch = signed_custody_epoch_for_node_keys([
        (
            node1.provisioned.node_public_key,
            node1.provisioned.node_custody_public_key,
        ),
        (
            node2.provisioned.node_public_key,
            node2.provisioned.node_custody_public_key,
        ),
        (
            node3.provisioned.node_public_key,
            node3.provisioned.node_custody_public_key,
        ),
    ]);
    let fixtures_by_node = BTreeMap::from([
        (node1.provisioned.node_public_key, node1),
        (node2.provisioned.node_public_key, node2),
        (node3.provisioned.node_public_key, node3),
    ]);
    let ordered_node_keys = custody_epoch
        .statement()
        .nodes()
        .iter()
        .map(|node| node.node_public_key())
        .collect::<Vec<_>>();
    let ordered_fixtures = ordered_node_keys
        .iter()
        .map(|node_public_key| fixtures_by_node.get(node_public_key).unwrap())
        .collect::<Vec<_>>();

    let provisioning_now = crate::auth::now_ts();
    let signed_pool = signed_custody_pool_for_epoch(
        &custody_epoch,
        (provisioning_now.saturating_sub(10), provisioning_now + 10),
    );
    let signed_committee_authorization = signed_committee_authorization_for_epoch(
        signed_pool.pool_identity().unwrap(),
        &custody_epoch,
    );
    let (clear_init_segment, clear_segments) = clear_media_components(0x11);
    let protect_registry = Arc::new(ProviderRegistry::new());
    let protect_bridge = ProviderBridge::spawn(
        &protect_binary,
        ProviderConfig {
            extra: json!({}),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let protect_provider: Arc<dyn Provider> = Arc::new(CapsuleProvider::with_scheme(
        Arc::new(protect_bridge),
        "protect",
    ));
    protect_registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect_provider)
        .await
        .unwrap();
    let protect_nodes = ordered_fixtures
        .iter()
        .map(|fixture| {
            ProtectionSessionNodeV1::new(
                fixture.provisioned.node_public_key,
                fixture.provisioned.node_custody_public_key,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let opened = invoke_typed_protect_provider(
        protect_registry.as_ref(),
        "open_protection_session",
        &ProtectProviderRequestV1::new_open_protection_session(
            digest(0xb1),
            content_access_id(0x41),
            signed_pool.pool_identity().unwrap(),
            custody_epoch.epoch_identity().unwrap(),
            signed_committee_authorization
                .authorization_identity()
                .unwrap(),
            MEDIA_MIME_TYPE_V1,
            MEDIA_CODECS_V1,
            u32::try_from(clear_segments.len()).unwrap(),
            &clear_init_segment,
            protect_nodes,
        )
        .unwrap(),
    )
    .await;
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionOpened
    );
    let protection_session_handle = opened.protection_session_handle().unwrap().unwrap();
    let protected_init_segment = opened.protected_init_segment().unwrap().to_vec();
    let mut encrypted_segments = Vec::with_capacity(clear_segments.len());
    for (segment_index, clear_segment) in clear_segments.iter().enumerate() {
        let protected = invoke_typed_protect_provider(
            protect_registry.as_ref(),
            "protect_media_segment",
            &ProtectProviderRequestV1::new_protect_media_segment(
                protection_session_handle,
                u32::try_from(segment_index).unwrap(),
                clear_segment,
            )
            .unwrap(),
        )
        .await;
        assert_eq!(
            protected.status(),
            ProtectProviderResponseStatusV1::MediaSegmentProtected
        );
        assert_eq!(
            protected.segment_index(),
            Some(u32::try_from(segment_index).unwrap())
        );
        encrypted_segments.push(protected.protected_segment().unwrap().to_vec());
    }
    let finalized = invoke_typed_protect_provider(
        protect_registry.as_ref(),
        "finalize_protection_session",
        &ProtectProviderRequestV1::new_finalize_protection_session(protection_session_handle)
            .unwrap(),
    )
    .await;
    assert_eq!(
        finalized.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionFinalized
    );
    let protected_media_identity = finalized.media_identity().unwrap().unwrap();
    let envelope = finalized.custody_envelope().unwrap().unwrap();
    assert_eq!(
        protected_media_identity,
        CencFmp4MediaIdentityV1::new_from_bytes(
            &protected_init_segment,
            &encrypted_segments,
            MEDIA_MIME_TYPE_V1,
            MEDIA_CODECS_V1,
        )
        .unwrap()
    );
    assert_eq!(
        envelope.manifest().encrypted_content(),
        protected_media_identity.encrypted_content()
    );
    assert_eq!(
        envelope.manifest().custody_pool(),
        signed_pool.pool_identity().unwrap()
    );
    assert_eq!(
        envelope.manifest().custody_epoch(),
        custody_epoch.epoch_identity().unwrap()
    );
    assert_eq!(
        envelope.manifest().custody_committee_authorization(),
        signed_committee_authorization
            .authorization_identity()
            .unwrap()
    );
    assert_eq!(
        envelope.manifest().threshold(),
        ThresholdV1::new(2, 3).unwrap()
    );
    assert_eq!(
        envelope.manifest().nodes(),
        custody_epoch.statement().nodes()
    );
    let protect_closed = invoke_typed_protect_provider(
        protect_registry.as_ref(),
        "close_protection_session",
        &ProtectProviderRequestV1::new_close_protection_session(protection_session_handle).unwrap(),
    )
    .await;
    assert_eq!(
        protect_closed.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionClosed
    );

    let mint_nodes = ordered_fixtures
        .iter()
        .enumerate()
        .map(|(index, fixture)| {
            let node_seed = u8::try_from(index + 1).unwrap();
            RuntimeMintNodeBinding::new(
                fixture.provisioned.node_public_key,
                CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
                fixture.owner_state_root,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mint_draft = RuntimeMintDraft::new(
        &protected_init_segment,
        &encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
        content_access_id(0x41),
        envelope.key_envelope_identity().unwrap(),
        policy_body().policy_identity().unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        mint_nodes.clone(),
    )
    .unwrap();
    let mint_owner_parent = temp_root.join("runtime-mint-owner-only-parent");
    owner_only_dir(&mint_owner_parent);
    let mint_root = mint_owner_parent.join("runtime-mint");
    let mint_selected = mint_nodes
        .iter()
        .zip(ordered_fixtures.iter())
        .map(|(binding, fixture)| RuntimeMintSelectedNode::new(binding.clone(), &fixture.adapter))
        .collect::<Vec<_>>();
    let mint_coordinator = RuntimeMintCoordinator::new(
        RuntimeMintJournal::new(mint_root.clone()),
        runtime_operation_issuer_for_seed(0x21),
        sign_runtime_statement_for_seed_0x21,
        mint_selected,
    )
    .unwrap();
    let mint_outcome = mint_coordinator
        .provision(&mint_draft, &envelope, provisioning_now)
        .await
        .unwrap();
    match mint_outcome {
        RuntimeMintCoordinatorOutcome::CustodyProvisioned { mint_id } => {
            assert_eq!(mint_id, mint_draft.mint_id());
        }
        other => panic!("unexpected mint outcome: {other:?}"),
    }
    let mint_journal = RuntimeMintJournal::new(mint_root.clone());
    let custody_provisioned = mint_journal.load(mint_draft.mint_id()).unwrap();
    assert!(custody_provisioned.all_receipts_present());
    assert_eq!(
        custody_provisioned.uncertain_node_count(),
        0,
        "every node answered with a receipt, so none is left possibly holding a share"
    );
    assert_eq!(custody_provisioned.accepted_orphans().len(), 3);
    let sealed_share_bytes = envelope.stored_shares()[0].canonical_bytes().unwrap();
    assert!(!any_file_contains(&mint_root, &sealed_share_bytes));
    assert!(!any_file_contains(&mint_root, &protected_init_segment));
    assert!(!any_file_contains(&mint_root, &encrypted_segments[0]));
    assert!(!any_file_contains(&mint_root, &clear_init_segment));
    assert!(!any_file_contains(&mint_root, &clear_segments[0]));

    let content_provider = ContentAvailabilityTestProvider::new(
        0x61,
        ContentAvailabilityTestConfig {
            checked_at: crate::auth::now_ts(),
            ..ContentAvailabilityTestConfig::accepted()
        },
    );
    let requirement = availability_requirement(content_provider.signer_did());
    let content_registry = Arc::new(ProviderRegistry::new());
    content_registry
        .register_sub_provider("content", content_provider)
        .await
        .unwrap();
    let content_directory = protected_content_directory_from_parts(
        &protected_init_segment,
        &encrypted_segments,
        &protected_media_identity,
    );
    let availability_evidence = publish_and_verify_v1_protected_content_for_test(
        content_registry.as_ref(),
        content_directory.path(),
        mint_draft.media_identity().unwrap(),
        &requirement,
        crate::auth::now_ts,
    )
    .await
    .unwrap();
    let availability_outcome = mint_coordinator
        .record_content_availability(&mint_draft, &requirement, availability_evidence)
        .unwrap();
    match availability_outcome {
        RuntimeMintCoordinatorOutcome::ContentAvailable { mint_id } => {
            assert_eq!(mint_id, mint_draft.mint_id());
        }
        other => panic!("unexpected availability outcome: {other:?}"),
    }
    let mint = mint_journal.load(mint_draft.mint_id()).unwrap();
    assert!(mint.content_availability().is_some());

    let purchase_effect = runtime_verified_purchase_effect_for_mint(
        &mint,
        "profile:alpha",
        "wallet-account-alpha",
        "wallet-request:11111111111111111111111111111111",
        0xaa,
        crate::auth::now_ts(),
    );
    let profile = ProfileIdentityV1::from_public_key_bytes(
        SigningKey::from_bytes(&[0x26; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let session_a = RuntimeSessionBindingV1::new(digest(0x66)).unwrap();
    let session_b = RuntimeSessionBindingV1::new(digest(0x67)).unwrap();
    let preliminary_buy = bind_buy(&mint, "profile:alpha", profile, &purchase_effect).unwrap();
    assert_eq!(
        preliminary_buy.binding_for_session(session_a).unwrap(),
        binding_for_envelope(&envelope)
    );
    assert_eq!(preliminary_buy.action(), RightsActionV1::View);

    let decrypt_registry = Arc::new(ProviderRegistry::new());
    register_protected_content_decrypt_provider(
        &decrypt_registry,
        &decrypt_binary,
        runtime_operation_issuer_for_seed(0x21),
    )
    .await
    .unwrap();
    let decrypt = RuntimeDecryptRegistryAdapter::new(decrypt_registry.clone());

    let flow_now = crate::auth::now_ts();
    let audit_a =
        super::runtime_open_audit_id("profile:alpha", preliminary_buy.mint_id(), flow_now);
    let audit_b =
        super::runtime_open_audit_id("profile:alpha", preliminary_buy.mint_id(), flow_now);
    let prepare_issued_at = flow_now.saturating_sub(5);
    let prepare_expires_at = flow_now + 240;
    let prepared_a = prepare_recipient(
        &decrypt,
        &preliminary_buy,
        session_a,
        audit_a,
        runtime_operation_issuer_for_seed(0x21),
        prepare_issued_at,
        prepare_expires_at,
    )
    .await
    .unwrap();
    let replayed_a = prepare_recipient(
        &decrypt,
        &preliminary_buy,
        session_a,
        audit_a,
        runtime_operation_issuer_for_seed(0x21),
        prepare_issued_at,
        prepare_expires_at,
    )
    .await
    .unwrap();
    assert_eq!(replayed_a, prepared_a);
    let prepared_b = prepare_recipient(
        &decrypt,
        &preliminary_buy,
        session_b,
        audit_b,
        runtime_operation_issuer_for_seed(0x21),
        prepare_issued_at,
        prepare_expires_at,
    )
    .await
    .unwrap();
    assert_ne!(prepared_a.binding(), prepared_b.binding());

    let operation = make_signed_runtime_release_operation_for_envelope_and_epoch_and_recipient_at(
        0x21,
        &envelope,
        custody_epoch.clone(),
        *prepared_a.recipient_public_key(),
        prepared_a.recipient_identity().clone(),
        audit_a,
        flow_now,
    );
    assert_eq!(
        prepared_a.binding(),
        operation.statement().rights_request().request().binding()
    );
    let (wallet_request, wallet_response) = wallet_request_response_for_release_at(
        &operation,
        "profile:alpha",
        "wallet-account-alpha",
        "wallet-request:11111111111111111111111111111111",
        flow_now,
    );
    let buy = bind_buy(&mint, "profile:alpha", profile, &purchase_effect).unwrap();

    let rights_request_1 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[0].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let rights_request_2 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[1].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let rights_request_3 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[2].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let chain1 = ProcessChainEvidenceProvider::new(rights_request_1, true);
    let chain2 = ProcessChainEvidenceProvider::new(rights_request_2, true);
    let chain3 = ProcessChainEvidenceProvider::new(rights_request_3, true);
    ordered_fixtures[0]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain1.clone())
        .await
        .unwrap();
    ordered_fixtures[1]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain2.clone())
        .await
        .unwrap();
    ordered_fixtures[2]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain3.clone())
        .await
        .unwrap();

    let runtime_owner_parent = temp_root.join("runtime-owner-only-parent");
    owner_only_dir(&runtime_owner_parent);
    let runtime_data_dir = runtime_owner_parent.join("runtime-release");
    let coordinator = RuntimeReleaseCoordinator::new(
        RuntimeReleaseJournal::new(runtime_data_dir.clone()),
        runtime_operation_issuer_for_seed(0x21),
        vec![
            RuntimeSelectedProvider::new(
                ordered_fixtures[0].provisioned.node_public_key,
                &ordered_fixtures[0].adapter,
                &ordered_fixtures[0].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[1].provisioned.node_public_key,
                &ordered_fixtures[1].adapter,
                &ordered_fixtures[1].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[2].provisioned.node_public_key,
                &ordered_fixtures[2].adapter,
                &ordered_fixtures[2].adapter,
            ),
        ],
    )
    .unwrap()
    .with_response_clock(crate::auth::now_ts);
    let outcome = coordinator
        .release(
            &wallet_request,
            &wallet_response,
            operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    let signed_node_contributions = match outcome {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::ContributionsReady {
                signed_node_contributions,
            },
        ) => signed_node_contributions,
        other => panic!("unexpected coordinator outcome: {other:?}"),
    };
    assert_eq!(signed_node_contributions.len(), 2);
    assert_eq!(chain1.requests().await.len(), 1);
    assert_eq!(chain2.requests().await.len(), 1);
    assert_eq!(chain3.requests().await.len(), 0);
    let expected_terminal = RuntimeReleaseCoordinatorOutcome::Terminal(
        RuntimeReleaseTerminalResult::ContributionsReady {
            signed_node_contributions: signed_node_contributions.clone(),
        },
    );
    let replay_coordinator = RuntimeReleaseCoordinator::new(
        RuntimeReleaseJournal::new(runtime_data_dir.clone()),
        runtime_operation_issuer_for_seed(0x21),
        vec![
            RuntimeSelectedProvider::new(
                ordered_fixtures[0].provisioned.node_public_key,
                &ordered_fixtures[0].adapter,
                &ordered_fixtures[0].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[1].provisioned.node_public_key,
                &ordered_fixtures[1].adapter,
                &ordered_fixtures[1].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[2].provisioned.node_public_key,
                &ordered_fixtures[2].adapter,
                &ordered_fixtures[2].adapter,
            ),
        ],
    )
    .unwrap()
    .with_response_clock(crate::auth::now_ts);
    let replay_outcome = replay_coordinator
        .release(
            &wallet_request,
            &wallet_response,
            operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    assert_eq!(replay_outcome, expected_terminal);
    assert_eq!(chain1.requests().await.len(), 1);
    assert_eq!(chain2.requests().await.len(), 1);
    assert_eq!(chain3.requests().await.len(), 0);
    assert!(list_unresolved_runtime_releases(&runtime_data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&runtime_data_dir)
        .unwrap()
        .is_empty());

    let terminal_receipt = make_signed_terminal_receipt_at(
        &operation,
        &signed_node_contributions,
        0x61,
        crate::auth::now_ts(),
    );

    let wrong_open = open_viewer_session(
        &decrypt,
        &RuntimeOpenViewerSessionInput {
            buy: &buy,
            prepared_recipient: &prepared_b,
            signed_runtime_release_operation: &operation,
            expected_terminal_issuer: terminal_receipt.statement().issuer(),
            content_key_commitment: envelope.manifest().content_key_commitment(),
            content: RuntimeOpenViewerContentV1::Media {
                media_identity: &protected_media_identity,
                protected_init_segment: &protected_init_segment,
            },
            signed_node_contributions: &signed_node_contributions,
            signed_terminal_receipt: &terminal_receipt,
            now_unix_seconds: crate::auth::now_ts(),
        },
    )
    .await;
    assert_eq!(wrong_open, Err(RuntimeOpenError::MintSelection));
    cancel_prepared_recipient(&decrypt, &prepared_b)
        .await
        .unwrap();
    cancel_prepared_recipient(&decrypt, &prepared_b)
        .await
        .unwrap();
    let wrong_media_identity = media_identity(0x41);
    let wrong_object_open = open_viewer_session(
        &decrypt,
        &RuntimeOpenViewerSessionInput {
            buy: &buy,
            prepared_recipient: &prepared_a,
            signed_runtime_release_operation: &operation,
            expected_terminal_issuer: terminal_receipt.statement().issuer(),
            content_key_commitment: envelope.manifest().content_key_commitment(),
            content: RuntimeOpenViewerContentV1::Media {
                media_identity: &wrong_media_identity,
                protected_init_segment: &protected_init_segment,
            },
            signed_node_contributions: &signed_node_contributions,
            signed_terminal_receipt: &terminal_receipt,
            now_unix_seconds: crate::auth::now_ts(),
        },
    )
    .await;
    assert_eq!(wrong_object_open, Err(RuntimeOpenError::DecryptResult));

    let session = open_viewer_session(
        &decrypt,
        &RuntimeOpenViewerSessionInput {
            buy: &buy,
            prepared_recipient: &prepared_a,
            signed_runtime_release_operation: &operation,
            expected_terminal_issuer: terminal_receipt.statement().issuer(),
            content_key_commitment: envelope.manifest().content_key_commitment(),
            content: RuntimeOpenViewerContentV1::Media {
                media_identity: &protected_media_identity,
                protected_init_segment: &protected_init_segment,
            },
            signed_node_contributions: &signed_node_contributions,
            signed_terminal_receipt: &terminal_receipt,
            now_unix_seconds: crate::auth::now_ts(),
        },
    )
    .await
    .unwrap();

    let clear_init = read_viewer_media_part(
        &decrypt,
        &session,
        ViewerMediaPartSelectorV1::init(),
        crate::auth::now_ts(),
    )
    .await
    .unwrap();
    assert_eq!(clear_init.clear_media_part(), clear_init_segment.as_slice());

    let mut tampered_segment = encrypted_segments[1].clone();
    tampered_segment[0] ^= 0x01;
    let tampered_selector = ViewerMediaPartSelectorV1::segment(1, tampered_segment).unwrap();
    assert_eq!(
        read_viewer_media_part(&decrypt, &session, tampered_selector, crate::auth::now_ts(),).await,
        Err(RuntimeOpenError::DecryptResult)
    );

    let selector = ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap();
    let clear_segment =
        read_viewer_media_part(&decrypt, &session, selector.clone(), crate::auth::now_ts())
            .await
            .unwrap();
    let clear_segment_replay =
        read_viewer_media_part(&decrypt, &session, selector.clone(), crate::auth::now_ts())
            .await
            .unwrap();
    assert_eq!(clear_segment.part_selector(), &selector);
    assert_eq!(
        clear_segment.clear_media_part(),
        clear_segment_replay.clear_media_part()
    );
    assert_eq!(
        clear_segment.clear_media_part(),
        clear_segments[1].as_slice()
    );

    close_viewer_session(&decrypt, &session).await.unwrap();
    close_viewer_session(&decrypt, &session).await.unwrap();
    cancel_prepared_recipient(&decrypt, &prepared_a)
        .await
        .unwrap();
    let audit_c =
        super::runtime_open_audit_id("profile:alpha", preliminary_buy.mint_id(), flow_now);
    let prepared_c = prepare_recipient(
        &decrypt,
        &preliminary_buy,
        session_a,
        audit_c,
        runtime_operation_issuer_for_seed(0x21),
        prepare_issued_at,
        prepare_expires_at,
    )
    .await
    .unwrap();
    assert_ne!(
        prepared_c.prepared_recipient_handle(),
        session.viewer_session_handle()
    );
    cancel_prepared_recipient(&decrypt, &prepared_c)
        .await
        .unwrap();

    let session_debug = format!("{session:?}");
    let init_debug = format!("{clear_init:?}");
    let segment_debug = format!("{clear_segment:?}");
    assert!(!session_debug.contains("carrier-provider-plane"));
    assert!(!session_debug.contains("node-1"));
    assert!(!session_debug.contains("node-2"));
    assert!(!session_debug.contains("node-3"));
    assert!(!init_debug.contains("share"));
    assert!(!segment_debug.contains("share"));
    assert!(!segment_debug.contains("cek"));

    assert!(!any_file_contains(&runtime_data_dir, &sealed_share_bytes));
    assert!(!any_file_contains(
        &runtime_data_dir,
        &protected_init_segment
    ));
    assert!(!any_file_contains(
        &runtime_data_dir,
        &encrypted_segments[0]
    ));
    assert!(!any_file_contains(&runtime_data_dir, &clear_init_segment));
    assert!(!any_file_contains(&runtime_data_dir, &clear_segments[0]));

    decrypt_registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();
    let mut schemes = decrypt_registry.sub_provider_schemes().await;
    schemes.sort();
    assert_eq!(schemes, Vec::<String>::new());
    protect_registry
        .unregister_runtime_provider_target(PROTECT_PROVIDER_ID)
        .await
        .unwrap();
    let mut protect_schemes = protect_registry.sub_provider_schemes().await;
    protect_schemes.sort();
    assert_eq!(protect_schemes, Vec::<String>::new());
    assert_eq!(
        prepare_recipient(
            &decrypt,
            &buy,
            RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
            RuntimeReleaseAuditIdV1::new(digest(0xaf)).unwrap(),
            runtime_operation_issuer_for_seed(0x21),
            crate::auth::now_ts(),
            crate::auth::now_ts() + 45,
        )
        .await,
        Err(RuntimeOpenError::DecryptResult)
    );

    assert!(list_unresolved_runtime_releases(&runtime_data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&runtime_data_dir)
        .unwrap()
        .is_empty());

    for fixture in ordered_fixtures {
        fixture
            .registry
            .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
            .unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn custody_registration_rejects_missing_or_unsafe_root_before_provider_use() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("missing-data");
    owner_only_dir(&data_dir);
    let (binary, pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    let error = register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing or unsafe"));
    assert!(!error.to_string().contains(temp.path().to_str().unwrap()));
    assert!(!request_log.exists());
    assert!(!pid_file.exists());

    let unsafe_data_dir = temp.path().join("unsafe-data");
    owner_only_dir(&unsafe_data_dir);
    let unsafe_root = inactive_custody_state_root(&unsafe_data_dir);
    owner_only_dir(&unsafe_root);
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o755)).unwrap();
    // Plan B T2.1 (user 10:26): the Home's root set names an unsafe root and
    // starts the others (`custody_registration_names_an_unsafe_root_and_starts_the_others`);
    // the custody host's one legacy root is still refused before any use.
    let error = register_custody_host_provider(&registry, &binary, &unsafe_data_dir)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing or unsafe"));
    assert!(!error.to_string().contains(temp.path().to_str().unwrap()));
    assert!(!request_log.exists());
    assert!(!pid_file.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn inactive_custody_registry_unregisters_shutdowns_and_restarts_bridge() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let first_pid = read_pid(&pid_file);

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(first_pid));

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let second_pid = read_pid(&pid_file);
    assert_ne!(first_pid, second_pid);
    let response = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({"op": "release_contribution"}),
    )
    .await
    .unwrap();
    assert_eq!(response["echo"], "custody");

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(second_pid));
}

#[cfg(unix)]
#[tokio::test]
async fn inactive_custody_duplicate_registration_rejects_and_settles_rejected_child() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let first_pid = read_pid(&pid_file);

    let error = register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("failed to register inactive custody route"));

    let pids = read_pids(&pid_file);
    assert_eq!(pids.len(), 2);
    let rejected_pid = *pids.last().unwrap();
    assert_ne!(first_pid, rejected_pid);
    assert!(process_is_running(first_pid));
    assert!(!process_is_running(rejected_pid));

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn protected_content_decrypt_startup_rejects_invalid_status_and_settles_child() {
    let issuer = runtime_operation_issuer_for_seed(0x41);
    let mut cases = Vec::new();
    let mut wrong_identity = protected_content_decrypt_provider_status();
    wrong_identity["data"]["provider"] = json!("decrypt");
    cases.push(("identity", wrong_identity));
    let mut wrong_request_schema = protected_content_decrypt_provider_status();
    wrong_request_schema["data"]["request_schema"] = json!("wrong-request-schema");
    cases.push(("request-schema", wrong_request_schema));
    let mut wrong_response_schema = protected_content_decrypt_provider_status();
    wrong_response_schema["data"]["response_schema"] = json!("wrong-response-schema");
    cases.push(("response-schema", wrong_response_schema));
    let mut wrong_version = protected_content_decrypt_provider_status();
    wrong_version["data"]["version"] = json!("wrong-version");
    cases.push(("version", wrong_version));
    let mut unconfigured = protected_content_decrypt_provider_status();
    unconfigured["data"]["configured"] = json!(false);
    cases.push(("configured", unconfigured));
    let mut wrong_operations = protected_content_decrypt_provider_status();
    wrong_operations["data"]["supported_operations"] = json!(["status", "shutdown"]);
    cases.push(("operations", wrong_operations));
    let mut extra_data = protected_content_decrypt_provider_status();
    extra_data["data"]["route"] = json!("private");
    cases.push(("extra-data", extra_data));
    let mut extra_top = protected_content_decrypt_provider_status();
    extra_top["route"] = json!("private");
    cases.push(("extra-top", extra_top));

    for (name, status) in cases {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join(name);
        fs::create_dir_all(&case_root).unwrap();
        let (binary, pid_file, request_log) =
            write_mock_protected_content_decrypt_provider(&case_root, issuer, &status);
        let registry = Arc::new(ProviderRegistry::new());

        register_protected_content_decrypt_provider(&registry, &binary, issuer)
            .await
            .expect_err("invalid protected-content decrypt status must fail closed");

        assert!(!process_is_running(read_pid(&pid_file)), "case {name}");
        let requests = fs::read_to_string(&request_log).unwrap();
        assert!(requests.contains(r#""op":"status""#), "case {name}");
        assert!(requests.contains(r#""op":"shutdown""#), "case {name}");
        assert!(matches!(
            registry
                .invoke_provider(ProviderInvocation {
                    source: RUNTIME_PROVIDER_ID.to_string(),
                    target: PROTECTED_CONTENT_DECRYPT_PROVIDER_ID.to_string(),
                    op: "status".to_string(),
                    request: json!({"op":"status"}),
                    transfer: ProviderTransfer::Json,
                    range: None,
                    progress: None,
                    transport: ProviderInvocationTransport::Local,
                })
                .await,
            Err(ProviderError::NoProvider(target))
                if target == PROTECTED_CONTENT_DECRYPT_PROVIDER_ID
        ));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn protected_content_decrypt_startup_rejects_wrong_issuer_and_settles_child() {
    let temp = tempfile::tempdir().unwrap();
    let expected_issuer = runtime_operation_issuer_for_seed(0x41);
    let supplied_issuer = runtime_operation_issuer_for_seed(0x42);
    let (binary, pid_file, request_log) = write_mock_protected_content_decrypt_provider(
        temp.path(),
        expected_issuer,
        &protected_content_decrypt_provider_status(),
    );
    let registry = Arc::new(ProviderRegistry::new());

    register_protected_content_decrypt_provider(&registry, &binary, supplied_issuer)
        .await
        .expect_err("a provider that rejects the Runtime issuer must fail closed");

    assert!(!process_is_running(read_pid(&pid_file)));
    let requests = fs::read_to_string(&request_log).unwrap();
    assert!(requests.contains(&format!(
        r#""trusted_runtime_issuer":"0x{}""#,
        hex::encode(supplied_issuer.as_bytes())
    )));
    assert!(requests.contains(r#""op":"shutdown""#));
    assert!(!requests.contains(r#""op":"status""#));
}

#[cfg(unix)]
#[tokio::test]
async fn protected_content_decrypt_duplicate_and_restart_settle_exact_processes() {
    let temp = tempfile::tempdir().unwrap();
    let issuer = runtime_operation_issuer_for_seed(0x41);
    let (binary, pid_file, request_log) = write_mock_protected_content_decrypt_provider(
        temp.path(),
        issuer,
        &protected_content_decrypt_provider_status(),
    );
    let registry = Arc::new(ProviderRegistry::new());

    register_protected_content_decrypt_provider(&registry, &binary, issuer)
        .await
        .unwrap();
    let first_pid = read_pid(&pid_file);
    assert!(process_is_running(first_pid));

    let duplicate = register_protected_content_decrypt_provider(&registry, &binary, issuer)
        .await
        .unwrap_err();
    assert!(duplicate.to_string().contains("already registered"));
    let duplicate_pids = read_pids(&pid_file);
    assert_eq!(duplicate_pids.len(), 2);
    let rejected_pid = duplicate_pids[1];
    assert!(process_is_running(first_pid));
    assert!(!process_is_running(rejected_pid));

    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(first_pid));

    register_protected_content_decrypt_provider(&registry, &binary, issuer)
        .await
        .unwrap();
    let replacement_pid = read_pid(&pid_file);
    assert_ne!(replacement_pid, first_pid);
    assert_ne!(replacement_pid, rejected_pid);
    assert!(process_is_running(replacement_pid));
    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(replacement_pid));

    let requests = fs::read_to_string(&request_log).unwrap();
    assert_eq!(requests.matches(r#""op":"shutdown""#).count(), 3);
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

#[tokio::test]
async fn runtime_resolve_rights_policy_recomputes_identity_and_rejects_mismatch() {
    let encrypted_content_identity = EncryptedContentIdentityV1::new(digest(0x51), 4096).unwrap();
    let access_id = content_access_id(0x51);
    let policy = policy_body_for(
        encrypted_content_identity.clone(),
        access_id,
        RightsActionV1::View,
    );
    let registry = Arc::new(ProviderRegistry::new());
    let chain = RecordingProvider::new(
        CHAIN_PROVIDER_ID,
        ok_provider_response(json!({
            "schema": CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1,
            "policy_body": format!("0x{}", hex::encode(policy.canonical_bytes().unwrap())),
        })),
    );
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
        .await
        .unwrap();
    let resolved = resolve_runtime_rights_policy(
        registry.as_ref(),
        &encrypted_content_identity,
        access_id,
        RightsActionV1::View,
    )
    .await
    .unwrap();
    assert_eq!(resolved.body(), &policy);
    assert_eq!(resolved.identity(), &policy.policy_identity().unwrap());

    let invocation = chain.requests().await;
    assert_eq!(invocation.len(), 1);
    assert_eq!(
        invocation[0]["_runtime_invocation"]["target"],
        Value::String(CHAIN_PROVIDER_ID.to_string())
    );
    assert_eq!(
        invocation[0]["op"],
        Value::String("resolve_protected_content_policy".to_string())
    );

    for mismatched_policy in [
        policy_body_for(encrypted_content(0x52), access_id, RightsActionV1::View),
        policy_body_for(
            encrypted_content_identity.clone(),
            content_access_id(0x52),
            RightsActionV1::View,
        ),
        policy_body_for(
            encrypted_content_identity.clone(),
            access_id,
            RightsActionV1::Download,
        ),
    ] {
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_sub_provider(
                CHAIN_PROVIDER_ID,
                RecordingProvider::new(
                    CHAIN_PROVIDER_ID,
                    ok_provider_response(json!({
                        "schema": CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1,
                        "policy_body": format!(
                            "0x{}",
                            hex::encode(mismatched_policy.canonical_bytes().unwrap())
                        ),
                    })),
                ),
            )
            .await
            .unwrap();
        assert!(resolve_runtime_rights_policy(
            registry.as_ref(),
            &encrypted_content_identity,
            access_id,
            RightsActionV1::View
        )
        .await
        .is_err());
    }
}

#[cfg(unix)]
fn media_preparation_source_input(
    root: &Path,
    principal_id: &str,
) -> RuntimeCustodyLibrarySourceInput {
    RuntimeCustodyLibrarySourceInput {
        listing: None,
        object_uri: format!(
            "{}/Documents/source.mp4",
            crate::auth::principal_localhost_root(principal_id)
        ),
        principal_id: principal_id.to_string(),
        source_file_path: root.join("source.mp4"),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "5".to_string(),
        channel: "0x0000000000000000000000000000000000000022".to_string(),
        pay_token: String::new(),
        source_storage: "protected_principal_root".to_string(),
        pool_did: None,
    }
}

#[cfg(unix)]
fn setup_media_preparation_root(temp: &Path) -> (PathBuf, PathBuf) {
    let data_dir = temp.join("data");
    owner_only_dir(&data_dir);
    let protected_root = data_dir.join("protected-content");
    owner_only_dir(&protected_root);
    let provider_root = protected_root.join("media-provider");
    owner_only_dir(&provider_root);
    let staging_root = provider_root.join("staging");
    owner_only_dir(&staging_root);
    let source_path = temp.join("source.mp4");
    fs::write(&source_path, b"bounded source media").unwrap();
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).unwrap();
    (data_dir, staging_root)
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
        super::RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE
    );
    assert!(!data_dir.join("protected-content/runtime-mint").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_fails_closed_without_device_key() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    write_owner_only_custody_composition_config(
        &data_dir,
        &custody_composition_config(
            now,
            custody_route_bindings(
                &epoch,
                [
                    RuntimeCustodyRouteTransportConfig::Local,
                    RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                        peer_did: peer_did_for_seed(0xa1),
                    },
                    RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                        peer_did: peer_did_for_seed(0xa2),
                    },
                ],
            ),
        ),
    );
    let error = publish_runtime_custody_library_object(
        &data_dir,
        Arc::new(ProviderRegistry::new()),
        library_publish_test_input(&data_dir, "person:local:runtime-custody-missing-device-key"),
    )
    .await
    .expect_err("missing device key must fail closed");
    assert!(
        error
            .to_string()
            .contains("local Runtime device signing key is missing"),
        "{error}"
    );
    assert!(!data_dir.join("protected-content/runtime-mint").exists());
}

#[cfg(unix)]
fn library_publish_test_routes(
    epoch: &SignedCustodyEpochV1,
) -> Vec<RuntimeCustodyRouteBindingConfig> {
    custody_route_bindings(
        epoch,
        [
            RuntimeCustodyRouteTransportConfig::Local,
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_for_seed(0xa1),
            },
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_for_seed(0xa2),
            },
        ],
    )
}

/// A v2 publish input over a prepared video + audio tree that
/// the REAL loader validated: the files are laid out under the data directory's
/// media-provider staging root, one operation directory per principal, and a
/// second call for the same principal loads the same files again.
#[cfg(unix)]
pub(crate) fn library_publish_test_input(
    data_dir: &Path,
    principal_id: &str,
) -> RuntimeCustodyLibraryPublishInput {
    library_publish_test_input_with_renditions(
        data_dir,
        principal_id,
        &[
            (TEST_PREPARED_VIDEO.kind, TEST_PREPARED_VIDEO.segments),
            (TEST_PREPARED_AUDIO.kind, TEST_PREPARED_AUDIO.segments),
        ],
    )
}

#[cfg(unix)]
fn library_publish_test_input_with_renditions(
    data_dir: &Path,
    principal_id: &str,
    renditions: &[(CencDashRenditionKindV2, usize)],
) -> RuntimeCustodyLibraryPublishInput {
    let operation_root = runtime_media_staging_root(data_dir)
        .join(hex::encode(sha2::Sha256::digest(principal_id.as_bytes())));
    if !operation_root.exists() {
        owner_only_dir(&protected_content_root(data_dir));
        owner_only_dir(&protected_content_root(data_dir).join("media-provider"));
        owner_only_dir(&runtime_media_staging_root(data_dir));
        owner_only_dir(&operation_root);
        write_prepared_media_v2(&operation_root, renditions);
    }
    RuntimeCustodyLibraryPublishInput {
        listing: None,
        object_uri: "localhost://Users/test/Documents/media".to_string(),
        principal_id: principal_id.to_string(),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "5".to_string(),
        channel: "0x0000000000000000000000000000000000000022".to_string(),
        pay_token: String::new(),
        media: load_runtime_prepared_media_v2(&operation_root, None).unwrap(),
        source_storage: "plain_localhost_root".to_string(),
        pool_did: None,
    }
}

#[cfg(unix)]
fn library_publish_request_id(input: &RuntimeCustodyLibraryPublishInput) -> Digest32 {
    RuntimeMintIntent::request_id_for_source(
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    )
    .unwrap()
}

#[cfg(unix)]
pub(crate) fn write_library_publish_test_composition(
    data_dir: &Path,
) -> (SignedCustodyEpochV1, u64) {
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    write_owner_only_custody_composition_config(
        data_dir,
        &custody_composition_config(now, library_publish_test_routes(&epoch)),
    );
    // Return the clock read used to derive the composition identities: the
    // custody-pool identity is content-addressed over clock-derived windows,
    // so any fixture that must produce the identical pool/committee identity
    // has to reuse this exact value instead of reading the clock again.
    (epoch, now)
}

#[cfg(unix)]
pub(crate) fn library_publish_test_mint_composition(
    data_dir: &Path,
) -> (
    Vec<RuntimeMintNodeBinding>,
    CustodyPoolIdentityV1,
    elastos_protected_content_contracts::CustodyEpochIdentityV1,
    CustodyCommitteeAuthorizationIdentityV1,
) {
    write_library_publish_test_composition(data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let composition = load_runtime_custody_composition(data_dir, registry)
        .unwrap()
        .unwrap();
    let configured = composition.configured_nodes().unwrap();
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        crate::auth::now_ts(),
        &configured,
    )
    .unwrap();
    let bindings = selected.iter().map(|node| node.binding().clone()).collect();
    let pool = composition.signed_pool.pool_identity().unwrap();
    let epoch = composition.signed_epoch.epoch_identity().unwrap();
    let committee = composition
        .signed_committee_authorization
        .authorization_identity()
        .unwrap();
    (bindings, pool, epoch, committee)
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

/// A prepared media that only DECLARES its layout (video and audio, two
/// segments each) and a receipt derived from `seed`, with nothing on disk. For
/// tests that seed a journal record and never run the mint over these files.
pub(crate) fn declared_prepared_media_for_test(seed: u8) -> super::RuntimePreparedMediaV2 {
    super::RuntimePreparedMediaV2 {
        operation_root: PathBuf::new(),
        renditions: [DASH_VIDEO, DASH_AUDIO]
            .into_iter()
            .map(|kind| super::RuntimePreparedRenditionV2 {
                kind,
                clear_init_segment: Vec::new(),
                timescale: 15360,
                segment_count: 2,
            })
            .collect(),
        preparation_receipt: digest(seed),
        clear_bytes: 0,
        part_reads: Arc::default(),
    }
}

/// The rendition kinds and segment counts a publish input declares.
#[cfg(unix)]
fn test_input_layout(
    input: &RuntimeCustodyLibraryPublishInput,
) -> (Vec<CencDashRenditionKindV2>, Vec<usize>) {
    input
        .media
        .renditions
        .iter()
        .map(|rendition| (rendition.kind, rendition.segment_count as usize))
        .unzip()
}

/// A protected package of the same layout as `input` (a fixture head and
/// ciphertext, not tied to the input's own bytes), for tests that seed a mint
/// record rather than run the protect.
#[cfg(unix)]
fn protected_dash_components_for_input(
    input: &RuntimeCustodyLibraryPublishInput,
) -> media_dash_fixture::MediaDashComponents {
    let (kinds, counts) = test_input_layout(input);
    media_dash_components(&kinds, &counts)
}

/// The v2 mint intent the production path would persist for `input`, bound to
/// `draft`'s access id and committee.
#[cfg(unix)]
fn test_media_dash_intent(
    input: &RuntimeCustodyLibraryPublishInput,
    draft: &RuntimeMintDraft,
    nodes: Vec<RuntimeMintNodeBinding>,
) -> RuntimeMintIntent {
    RuntimeMintIntent::new_media_dash(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.media.preparation_receipt(),
        input
            .media
            .renditions
            .iter()
            .map(
                |rendition| elastos_protected_content_runtime::RuntimeMintIntentRenditionV2 {
                    kind: rendition.kind,
                    segment_count: rendition.segment_count,
                },
            )
            .collect(),
        draft.content_access_id(),
        draft.pool(),
        draft.epoch(),
        draft.committee(),
        nodes,
    )
    .unwrap()
}

/// Seed the exact ELACITY-2307 crash state: a mint intent settled at
/// `SettledBeforeDraft(Closed)` alongside the durable mint work the completion
/// mark never named. `complete` selects the fully terminal record (custody
/// provisioned, availability recorded) or a partial-provision window.
/// Returns the seeded record's mint id.
#[cfg(unix)]
fn seed_settled_runtime_custody_mint_record(
    data_dir: &Path,
    input: &RuntimeCustodyLibraryPublishInput,
    complete: bool,
) -> Digest32 {
    let (node_bindings, pool_identity, epoch_identity, committee_identity) =
        library_publish_test_mint_composition(data_dir);
    let journal = runtime_mint_journal(data_dir);
    let components = protected_dash_components_for_input(input);
    let threshold = ThresholdV1::new(2, 3).unwrap();
    let node_set = elastos_protected_content_contracts::NodeSetV1::new(
        threshold,
        node_bindings
            .iter()
            .map(|node| node.node_public_key())
            .collect(),
    )
    .unwrap();
    let key_envelope = elastos_protected_content_contracts::KeyEnvelopeIdentityV1::new(
        components.head.encrypted_content().clone(),
        digest(0x52),
        256,
        node_set.node_set_id().unwrap(),
        threshold,
        pool_identity,
        epoch_identity,
        committee_identity,
    )
    .unwrap();
    let policy =
        elastos_protected_content_contracts::RightsPolicyIdentityV1::new(digest(0x56), 128)
            .unwrap();
    let draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::MediaDash(components.head.clone()),
        components.head.default_kid(),
        key_envelope,
        policy,
        digest(0x61),
        threshold,
        node_bindings.clone(),
    )
    .unwrap();
    let intent = test_media_dash_intent(input, &draft, node_bindings.clone());
    let request_id = intent.request_id();
    journal.persist_intent(&intent).unwrap();
    journal
        .mark_intent_protect_effect_started(request_id)
        .unwrap();
    journal
        .mark_intent_protect_closed_before_draft(request_id)
        .unwrap();
    journal.persist_bound(&draft).unwrap();
    if !complete {
        journal
            .mark_node_effect_started(draft.mint_id(), node_bindings[0].node_public_key())
            .unwrap();
        return draft.mint_id();
    }
    for (index, node) in node_bindings.iter().enumerate() {
        journal
            .mark_node_effect_started(draft.mint_id(), node.node_public_key())
            .unwrap();
        journal
            .mark_node_receipt(
                draft.mint_id(),
                RuntimeMintNodeReceipt::new(
                    node.node_public_key(),
                    RuntimeCustodyProvisioningIdV1::new(digest(0x71 + index as u8)).unwrap(),
                    CustodyNodeProvisioningRecordIdentityV1::new(
                        digest(0x81 + index as u8),
                        128 + index as u32,
                    )
                    .unwrap(),
                    node.owner_state_root(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    journal.mark_custody_provisioned(draft.mint_id()).unwrap();
    let content_id = runtime_protected_content_id(draft.encrypted_content()).unwrap();
    let requirement = RuntimeContentAvailabilityRequirement::new(
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe",
        content_id.clone(),
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
        "protected-content-replication/v1",
        3,
        600,
        60,
    )
    .unwrap();
    let evidence = elastos_protected_content_runtime::RuntimeVerifiedContentAvailability::new(
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        content_id,
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
        &requirement,
        3,
        crate::auth::now_ts(),
        digest(0xa1),
        draft.encrypted_content().clone(),
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media_dash(
            draft.media_dash_identity().unwrap(),
        ),
    )
    .unwrap();
    journal
        .mark_content_available(draft.mint_id(), &requirement, evidence)
        .unwrap();
    draft.mint_id()
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
/// A settled attempt that provisioned nothing durable and recorded no
/// availability can neither be rolled forward nor adopted, and its intent
/// settled before any draft existed. Keeping either of them makes the object
/// permanently unmintable, because the intent's identity is the object path.
///
/// This attempt still fails -- there is nothing to hand back -- but it leaves
/// nothing behind, so the creator's next attempt on that file starts from
/// nothing rather than meeting the same wall forever. Observed on Base: a node
/// restart mid-publish, and the file could not be minted again at all.
async fn runtime_custody_library_publish_clears_a_partial_settled_mint_so_the_object_mints_again() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let input =
        library_publish_test_input(&data_dir, "person:local:runtime-custody-partial-settled");
    let request_id = library_publish_request_id(&input);
    let mint_id = seed_settled_runtime_custody_mint_record(&data_dir, &input, false);

    let error =
        publish_runtime_custody_library_object(&data_dir, Arc::new(ProviderRegistry::new()), input)
            .await
            .expect_err("a settled attempt with nothing durable cannot be handed back");
    assert!(
        error
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{error}"
    );

    // Both are gone: nothing is left for the next attempt to collide with.
    assert!(
        runtime_mint_journal(&data_dir).load(mint_id).is_err(),
        "the unfinishable record must be discarded"
    );
    assert!(
        runtime_mint_journal(&data_dir)
            .load_intent(request_id)
            .is_err(),
        "the unmintable intent must be discarded"
    );

    // The object is mintable again: the next attempt gets past the wall that
    // used to be permanent, and fails for want of providers instead.
    let retried = publish_runtime_custody_library_object(
        &data_dir,
        Arc::new(ProviderRegistry::new()),
        library_publish_test_input(&data_dir, "person:local:runtime-custody-partial-settled"),
    )
    .await
    .expect_err("no providers are registered, so the fresh attempt still cannot finish");
    assert!(
        !retried
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "a cleared object must no longer abort before it starts: {retried}"
    );
}

#[cfg(unix)]
/// The publish input and the later media source must name the same object
/// under the principal's own root: the mint intent request id is derived
/// from the object binding, and a recovery-activated principal can only read
/// objects stored under its protected root.
fn pre_dispatch_retry_publish_input(data_dir: &Path) -> RuntimeCustodyLibraryPublishInput {
    let principal_id = "person:local:runtime-custody-pre-dispatch-retry";
    let mut input = library_publish_test_input(data_dir, principal_id);
    input.object_uri = format!(
        "{}/Documents/media",
        crate::auth::principal_localhost_root(principal_id)
    );
    input
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
async fn runtime_custody_library_publish_blocks_exact_retry_after_ambiguous_protect_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let _ = write_library_publish_test_composition(&data_dir);
    let protect = SequencedProvider::new(
        PROTECT_PROVIDER_ID,
        vec![
            Err(ProviderError::Provider(
                "simulated protect bridge failure".to_string(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_opened(
                    [0x51; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
                    b"placeholder-protected-init",
                )
                .unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_cancelled(
                    [0x51; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
                )
                .unwrap(),
            )),
        ],
    );
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();
    let input =
        library_publish_test_input(&data_dir, "person:local:runtime-custody-ambiguous-dispatch");
    let request_id = library_publish_request_id(&input);
    let first = publish_runtime_custody_library_object(&data_dir, registry.clone(), input)
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

    let second = publish_runtime_custody_library_object(
        &data_dir,
        registry.clone(),
        library_publish_test_input(&data_dir, "person:local:runtime-custody-ambiguous-dispatch"),
    )
    .await
    .expect_err("exact retry must recover and settle the ambiguous open");
    assert!(
        second
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{second}"
    );
    let settled = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert!(settled.protect_terminal_before_draft());
    assert_eq!(
        settled.protect_terminal_settlement_label(),
        Some("cancelled")
    );
    let requests = protect.requests().await;
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0]["op"], "open_protection_session");
    assert_eq!(requests[1]["op"], "open_protection_session");
    assert_eq!(requests[0], requests[1]);
    assert_eq!(requests[2]["op"], "cancel_protection_session");
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
async fn runtime_custody_library_publish_recovers_open_handle_by_cancelling_before_redispatch() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let _ = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let input = library_publish_test_input(
        &data_dir,
        "person:local:runtime-custody-open-handle-recovery",
    );
    let request_id = library_publish_request_id(&input);
    let composition = load_runtime_custody_composition(&data_dir, registry.clone())
        .unwrap()
        .unwrap();
    let configured = composition.configured_nodes().unwrap();
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        crate::auth::now_ts(),
        &configured,
    )
    .unwrap();
    let mint_nodes = selected
        .iter()
        .map(|node| node.binding().clone())
        .collect::<Vec<_>>();
    let journal = runtime_mint_journal(&data_dir);
    load_or_persist_runtime_mint_intent(&journal, &composition, &input, mint_nodes).unwrap();
    journal
        .mark_intent_protect_effect_started(request_id)
        .unwrap();
    let handle = [0x61; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    journal
        .mark_intent_protect_opened(request_id, handle)
        .unwrap();

    let protect = SequencedProvider::new(
        PROTECT_PROVIDER_ID,
        vec![Ok(ok_typed_protect_provider_response(
            ProtectProviderResponseV1::new_cancelled(handle).unwrap(),
        ))],
    );
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();

    let error = publish_runtime_custody_library_object(&data_dir, registry, input)
        .await
        .expect_err("open-handle recovery must settle by cancelling");
    assert!(
        error
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{error}"
    );
    let intent = journal.load_intent(request_id).unwrap();
    assert!(intent.protect_terminal_before_draft());
    assert_eq!(
        intent.protect_terminal_settlement_label(),
        Some("cancelled")
    );
    let requests = protect.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["op"], "cancel_protection_session");
}

/// A protect provider that answers from a script, and records what the mint
/// asked of it and how many clear parts the Runtime had read from disk at each
/// `protect_media_segment`, so a test can show a part is read, protected and
/// dropped before the next is read.
#[cfg(unix)]
struct MediaDashProtectTestProvider {
    responses: Mutex<VecDeque<Result<Value, ProviderError>>>,
    requests: Mutex<Vec<Value>>,
    part_reads: Option<Arc<std::sync::atomic::AtomicUsize>>,
    reads_at_segment_requests: Mutex<Vec<usize>>,
}

#[cfg(unix)]
impl MediaDashProtectTestProvider {
    fn new(
        responses: Vec<Result<Value, ProviderError>>,
        part_reads: Option<Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            part_reads,
            reads_at_segment_requests: Mutex::new(Vec::new()),
        })
    }

    async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }

    async fn reads_at_segment_requests(&self) -> Vec<usize> {
        self.reads_at_segment_requests.lock().await.clone()
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl Provider for MediaDashProtectTestProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "media dash protect test provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![PROTECT_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        PROTECT_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        if request["op"] == "protect_media_segment" {
            if let Some(part_reads) = &self.part_reads {
                self.reads_at_segment_requests
                    .lock()
                    .await
                    .push(part_reads.load(std::sync::atomic::Ordering::SeqCst));
            }
        }
        self.responses.lock().await.pop_front().unwrap_or_else(|| {
            Err(ProviderError::Provider(
                "media dash protect test provider script is exhausted".to_string(),
            ))
        })
    }
}

/// The protected package a protect provider honest about `input` would return
/// for `mint_intent`: every init rewritten under the intent's own header
/// (then handed to `steer_init`), every segment protected, the head over it,
/// and a key envelope for its ciphertext.
#[cfg(unix)]
fn protect_input_for_test(
    input: &RuntimeCustodyLibraryPublishInput,
    mint_intent: &RuntimeMintIntent,
    epoch: &SignedCustodyEpochV1,
    composition_now: u64,
    steer_init: &dyn Fn(usize, Vec<u8>) -> Vec<u8>,
) -> (media_dash_fixture::MediaDashComponents, CustodyEnvelopeV1) {
    let header = CustodyProtectionHeader::new(
        mint_intent.content_access_id(),
        &mint_intent.custody_pool(),
        &mint_intent.custody_epoch(),
        &mint_intent.custody_committee_authorization(),
        CencMediaSuite::DashV2,
    );
    let (kinds, counts) = test_input_layout(input);
    let components = media_dash_fixture::protect_media_dash_clear(
        mint_intent.content_access_id(),
        &header,
        &media_dash_fixture::clear_media_dash(&kinds, &counts),
        steer_init,
    );
    let committee = validated_custody_committee_for_epoch(epoch, composition_now);
    let content_key =
        elastos_protected_content_custody::ContentEncryptionKeyV1::generate().unwrap();
    let envelope = provision_custody_envelope(
        components.head.encrypted_content().clone(),
        &content_key,
        &committee,
    )
    .unwrap();
    (components, envelope)
}

/// The responses of an honest v2 protect, in the order a mint asks for them:
/// the open, every segment (video first, then audio), then the finalize.
/// The caller appends the settlement (`cancelled` or `closed`).
#[cfg(unix)]
fn media_dash_protect_script(
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    components: &media_dash_fixture::MediaDashComponents,
    envelope: &CustodyEnvelopeV1,
) -> Vec<Result<Value, ProviderError>> {
    let mut script = vec![Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_opened_v2(handle, &components.protected_inits).unwrap(),
    ))];
    for segments in &components.protected_segments {
        for (index, segment) in segments.iter().enumerate() {
            script.push(Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_segment_protected(handle, index as u32, segment)
                    .unwrap(),
            )));
        }
    }
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_finalized_v2(handle, &components.head, envelope).unwrap(),
    )));
    script
}

/// The persisted intent for `input` (what the mint would load or create), so a
/// test can build the protect response that matches its access id.
#[cfg(unix)]
fn persisted_test_mint_intent(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    input: &RuntimeCustodyLibraryPublishInput,
) -> RuntimeMintIntent {
    let composition = load_runtime_custody_composition(data_dir, registry.clone())
        .unwrap()
        .unwrap();
    let configured = composition.configured_nodes().unwrap();
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        crate::auth::now_ts(),
        &configured,
    )
    .unwrap();
    let mint_nodes = selected
        .iter()
        .map(|node| node.binding().clone())
        .collect::<Vec<_>>();
    load_or_persist_runtime_mint_intent(
        &runtime_mint_journal(data_dir),
        &composition,
        input,
        mint_nodes,
    )
    .unwrap()
}

/// Drives a full media publish against a protect provider whose protected init
/// segments are rebuilt by `steer`, and returns the resulting error string.
///
/// `steer` receives the mint intent, the rendition's position and the honest
/// protected init segment (the one this session's own identities produce) and
/// hands back the init the provider returns, so a caller can have the header
/// removed, replaced, or changed in one rendition only.
#[cfg(unix)]
async fn library_publish_error_with_steered_protection_header(
    principal: &str,
    steer: impl Fn(&RuntimeMintIntent, usize, Vec<u8>) -> Vec<u8>,
) -> String {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let (epoch, composition_now) = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let input = library_publish_test_input(&data_dir, principal);
    let mint_intent = persisted_test_mint_intent(&data_dir, &registry, &input);
    let (components, envelope) = protect_input_for_test(
        &input,
        &mint_intent,
        &epoch,
        composition_now,
        &|position, init| steer(&mint_intent, position, init),
    );
    let handle = [0x4b; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    let mut script = media_dash_protect_script(handle, &components, &envelope);
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_cancelled(handle).unwrap(),
    )));
    let protect = MediaDashProtectTestProvider::new(script, None);
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();

    let error = publish_runtime_custody_library_object(&data_dir, registry, input)
        .await
        .expect_err("a protect output whose protection header is wrong must not publish");
    let requests = protect.requests().await;
    assert_eq!(
        requests.last().map(|request| request["op"].clone()),
        Some(serde_json::json!("cancel_protection_session")),
        "the rejected session must still be settled: {requests:?}"
    );
    error.to_string()
}

/// The span `[start, start + size)` of the Elastos protection box in a
/// protected v2 init segment, and the offset of the `moov` box that holds it.
#[cfg(unix)]
fn elastos_protection_box_span(protected_init: &[u8]) -> (usize, usize, usize) {
    let writer = PROTECTION.writer().id;
    // A `pssh` box is size(4) type(4) version+flags(4) system id(16).
    let start = protected_init
        .windows(16)
        .position(|window| window == writer.as_bytes())
        .unwrap()
        - 12;
    let size = u32::from_be_bytes(protected_init[start..start + 4].try_into().unwrap()) as usize;
    let mut moov_off = 0;
    while &protected_init[moov_off + 4..moov_off + 8] != b"moov" {
        moov_off +=
            u32::from_be_bytes(protected_init[moov_off..moov_off + 4].try_into().unwrap()) as usize;
    }
    (start, size, moov_off)
}

/// A protected init segment with `replacement` (possibly nothing) in place of
/// its Elastos protection box, and the `moov` size fixed up.
#[cfg(unix)]
fn replace_protection_header(protected_init: &[u8], replacement: &[u8]) -> Vec<u8> {
    let (start, size, moov_off) = elastos_protection_box_span(protected_init);
    let mut steered = protected_init[..start].to_vec();
    steered.extend_from_slice(replacement);
    steered.extend_from_slice(&protected_init[start + size..]);
    let moov_size =
        u32::from_be_bytes(protected_init[moov_off..moov_off + 4].try_into().unwrap()) as usize;
    let resized = u32::try_from(moov_size - size + replacement.len()).unwrap();
    steered[moov_off..moov_off + 4].copy_from_slice(&resized.to_be_bytes());
    steered
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
#[tokio::test]
async fn runtime_custody_library_publish_retains_cleanup_obligation_when_close_fails() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let (epoch, composition_now) = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let input = library_publish_test_input(&data_dir, "person:local:runtime-custody-close-failure");
    let request_id = library_publish_request_id(&input);
    let mint_intent = persisted_test_mint_intent(&data_dir, &registry, &input);
    let (components, envelope) =
        protect_input_for_test(&input, &mint_intent, &epoch, composition_now, &|_, init| {
            init
        });
    let handle = [0x41; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    let mut script = media_dash_protect_script(handle, &components, &envelope);
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_failure(ProviderFailureCodeV1::BackendUnavailable).unwrap(),
    )));
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_already_absent(handle).unwrap(),
    )));
    let protect = MediaDashProtectTestProvider::new(script, None);
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();

    let first = publish_runtime_custody_library_object(&data_dir, registry.clone(), input)
        .await
        .expect_err("close failure must retain cleanup ownership");
    assert!(
        first
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE),
        "{first}"
    );
    let pending = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(
        pending.protect_state_label(),
        "open_handle_pending_close",
        "the close-failure scenario must reach the pending-close obligation; a \
         different label means the fixture was steered into another failure \
         mode: {pending:?}"
    );
    assert_eq!(
        pending.protect_pending_close_handle(),
        Some(handle),
        "{pending:?}"
    );

    let second = publish_runtime_custody_library_object(
        &data_dir,
        registry,
        library_publish_test_input(&data_dir, "person:local:runtime-custody-close-failure"),
    )
    .await
    .expect_err("close replay loss must settle via already_absent");
    assert!(
        second
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{second}"
    );
    let settled = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert!(settled.protect_terminal_before_draft());
    assert_eq!(
        settled.protect_terminal_settlement_label(),
        Some("already_absent")
    );
    let requests = protect.requests().await;
    // The open, four segments (two renditions of two), the finalize, and the
    // close that failed and the close that found the session already gone.
    assert_eq!(requests.len(), 8);
    assert_eq!(requests[6]["op"], "close_protection_session");
    assert_eq!(requests[7]["op"], "close_protection_session");
}

struct LibraryMintCustodyProvider {
    expected_issuer: RuntimeOperationIssuerKeyV1,
    nodes: Vec<NodePublicKey>,
}

#[async_trait::async_trait]
impl Provider for LibraryMintCustodyProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "library mint custody provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CUSTODY_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CUSTODY_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let mut request = request.clone();
        if let Some(object) = request.as_object_mut() {
            object.remove("_runtime_invocation");
        }
        if request.get("op").and_then(Value::as_str) != Some("provision_node_share") {
            return Err(ProviderError::Provider(
                "library mint custody provider expected provision_node_share".to_string(),
            ));
        }
        let bytes = serde_json::to_vec(&request)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let now = crate::auth::now_ts();
        for node in &self.nodes {
            let Ok(validated) = ValidatedCustodyProviderRequestV1::decode_and_validate_at(
                &bytes,
                self.expected_issuer,
                *node,
                now,
            ) else {
                continue;
            };
            let provision = validated.provision_node_share().map_err(|_| {
                ProviderError::Provider("library mint provision request is invalid".to_string())
            })?;
            let response = CustodyProviderResponseV1::new_provisioned(provision).map_err(|_| {
                ProviderError::Provider("library mint provision response is invalid".to_string())
            })?;
            let response = serde_json::from_slice(
                &response
                    .to_json_vec()
                    .map_err(|error| ProviderError::Provider(error.to_string()))?,
            )
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
            return Ok(ok_provider_response(response));
        }
        Err(ProviderError::Provider(
            "library mint custody provision did not match a selected node".to_string(),
        ))
    }
}

struct LibraryMintChainPolicyProvider;

#[async_trait::async_trait]
impl Provider for LibraryMintChainPolicyProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "library mint chain policy provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CHAIN_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CHAIN_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let encrypted_content = request
            .get("encrypted_content")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing encrypted_content".to_string()))
            .and_then(|value| {
                let hex = value.strip_prefix("0x").ok_or_else(|| {
                    ProviderError::Provider("invalid encrypted_content".to_string())
                })?;
                let bytes = hex::decode(hex).map_err(|_| {
                    ProviderError::Provider("invalid encrypted_content".to_string())
                })?;
                EncryptedContentIdentityV1::from_canonical_bytes(&bytes)
                    .map_err(|_| ProviderError::Provider("invalid encrypted_content".to_string()))
            })?;
        let content_access_id = request
            .get("content_access_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing content_access_id".to_string()))
            .and_then(|value| {
                let hex = value.strip_prefix("0x").ok_or_else(|| {
                    ProviderError::Provider("invalid content_access_id".to_string())
                })?;
                let bytes: [u8; 16] = hex::decode(hex)
                    .map_err(|_| ProviderError::Provider("invalid content_access_id".to_string()))?
                    .try_into()
                    .map_err(|_| {
                        ProviderError::Provider("invalid content_access_id".to_string())
                    })?;
                ContentAccessIdV1::new(bytes)
                    .map_err(|_| ProviderError::Provider("invalid content_access_id".to_string()))
            })?;
        if request.get("action").and_then(Value::as_str) != Some("view") {
            return Err(ProviderError::Provider(
                "unexpected policy action".to_string(),
            ));
        }
        let policy = policy_body_for(encrypted_content, content_access_id, RightsActionV1::View);
        Ok(ok_provider_response(json!({
            "schema": CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1,
            "policy_body": format!("0x{}", hex::encode(policy.canonical_bytes().unwrap())),
        })))
    }
}

struct LoopbackCustodyCarrierInvoker {
    registry: Weak<ProviderRegistry>,
}

#[async_trait::async_trait]
impl ProviderCarrierInvoker for LoopbackCustodyCarrierInvoker {
    async fn invoke_carrier_provider(
        &self,
        route: &ProviderCarrierRoute,
        invocation: &ProviderInvocation,
        mut request: Value,
    ) -> Result<Value, ProviderError> {
        if !matches!(route, ProviderCarrierRoute::PeerDid { .. }) {
            return Err(ProviderError::Provider(
                "library custody loopback requires an endpoint DID route".to_string(),
            ));
        }
        let runtime = request
            .get_mut("_runtime_invocation")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                ProviderError::Provider(
                    "library custody loopback requires a Runtime invocation envelope".to_string(),
                )
            })?;
        runtime.insert(
            "carrier".to_string(),
            json!({"source_endpoint_did": peer_did_for_seed(0xa0)}),
        );
        let registry = self.registry.upgrade().ok_or_else(|| {
            ProviderError::Provider("library mint carrier loopback registry is gone".to_string())
        })?;
        registry
            .send_runtime_provider_target_raw(&invocation.target, &request)
            .await
    }
}

struct AllowingProcessChainEvidenceProvider;

#[async_trait::async_trait]
impl Provider for AllowingProcessChainEvidenceProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "allowing process chain evidence provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CHAIN_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CHAIN_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        if request["_runtime_invocation"]["source"]
            != Value::String(RUNTIME_PROVIDER_ID.to_string())
            || request["_runtime_invocation"]["target"]
                != Value::String(CHAIN_PROVIDER_ID.to_string())
            || request["_runtime_invocation"]["op"]
                != Value::String(CHAIN_RIGHTS_EVIDENCE_OP.to_string())
            || request["_runtime_invocation"]["transport"]
                != Value::String("runtime-local-provider-plane".to_string())
            || request["_runtime_invocation"]["carrier"] != Value::Null
        {
            return Err(ProviderError::Provider(
                "chain evidence runtime envelope did not match the expected invocation".to_string(),
            ));
        }
        let mut inner_request = request.clone();
        let Some(inner_object) = inner_request.as_object_mut() else {
            return Err(ProviderError::Provider(
                "chain evidence request was not an object".to_string(),
            ));
        };
        inner_object.remove("_runtime_invocation");
        let signed_hex = inner_request
            .get("signed_runtime_release_operation")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::Provider(
                    "chain evidence request is missing the signed release operation".to_string(),
                )
            })?;
        let signed_bytes = hex::decode(signed_hex.strip_prefix("0x").unwrap_or(signed_hex))
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let operation = SignedRuntimeReleaseOperationV1::from_canonical_bytes(&signed_bytes)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let selected = operation
            .statement()
            .custody_epoch()
            .statement()
            .nodes()
            .first()
            .ok_or_else(|| {
                ProviderError::Provider("signed release operation has no custody nodes".to_string())
            })?
            .node_public_key();
        let expected = RightsProviderRequestV1::new_evaluate(selected, &operation)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let evidence_now = crate::auth::now_ts();
        Ok(ok_provider_response(chain_evidence_for_request_at(
            &expected,
            evidence_now,
            evidence_now,
            true,
        )))
    }
}

struct LibraryProcessCustodyDispatcher {
    expected_issuer: RuntimeOperationIssuerKeyV1,
    nodes: Vec<(NodePublicKey, Arc<ProviderRegistry>)>,
}

impl LibraryProcessCustodyDispatcher {
    fn strip_envelope(request: &Value) -> Result<Value, ProviderError> {
        let mut inner = request.clone();
        if let Some(object) = inner.as_object_mut() {
            object.remove("_runtime_invocation");
        }
        Ok(inner)
    }

    fn node_registry(&self, request: &Value) -> Result<Arc<ProviderRegistry>, ProviderError> {
        let inner = Self::strip_envelope(request)?;
        let op = inner
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let bytes = serde_json::to_vec(&inner)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let now = crate::auth::now_ts();
        match op.as_str() {
            "status" => self
                .nodes
                .first()
                .map(|(_, registry)| registry.clone())
                .ok_or_else(|| {
                    ProviderError::Provider(
                        "library process custody dispatcher has no nodes".to_string(),
                    )
                }),
            "evaluate" => {
                let validated =
                    ValidatedRightsProviderRequestV1::decode_and_validate_at(&bytes, now)
                        .map_err(|error| ProviderError::Provider(error.to_string()))?;
                self.nodes
                    .iter()
                    .find(|(node, _)| *node == validated.selected_node_public_key())
                    .map(|(_, registry)| registry.clone())
                    .ok_or_else(|| {
                        ProviderError::Provider(
                            "library process custody evaluate did not match a selected node"
                                .to_string(),
                        )
                    })
            }
            "provision_node_share" | "release_contribution" => {
                for (node, registry) in &self.nodes {
                    if ValidatedCustodyProviderRequestV1::decode_and_validate_at(
                        &bytes,
                        self.expected_issuer,
                        *node,
                        now,
                    )
                    .is_ok()
                    {
                        return Ok(registry.clone());
                    }
                }
                Err(ProviderError::Provider(
                    "library process custody request did not match a selected node".to_string(),
                ))
            }
            _ => Err(ProviderError::Provider(format!(
                "library process custody dispatcher rejected op {op}"
            ))),
        }
    }
}

#[async_trait::async_trait]
impl Provider for LibraryProcessCustodyDispatcher {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "library process custody dispatcher is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CUSTODY_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CUSTODY_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let registry = self.node_registry(request)?;
        registry
            .send_runtime_provider_target_raw(CUSTODY_PROVIDER_ID, request)
            .await
    }
}

struct LibraryReleaseWalletProvider;

#[async_trait::async_trait]
impl Provider for LibraryReleaseWalletProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "library release wallet provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["wallet"]
    }

    fn name(&self) -> &'static str {
        "wallet"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let inner = request.get("request").cloned().ok_or_else(|| {
            ProviderError::Provider("wallet request is missing the v2 envelope".to_string())
        })?;
        let bytes = serde_json::to_vec(&inner)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let now = crate::auth::now_ts();
        let wallet_request = WalletProviderRequestV2::decode_at(&bytes, now)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let (account_id, canonical_rights_request_hex) = match &wallet_request.operation {
            WalletProviderOperationV2::RequestProtectedContentRightsSignature {
                account_id,
                canonical_rights_request_hex,
                ..
            } => (account_id.clone(), canonical_rights_request_hex.clone()),
            _ => {
                return Err(ProviderError::Provider(
                    "library release wallet expected a protected-content rights signature"
                        .to_string(),
                ));
            }
        };
        let rights_bytes = hex::decode(&canonical_rights_request_hex)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let rights_request = RightsRequestV1::from_canonical_bytes(&rights_bytes)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let key = WalletSigningKey::from_slice(&[7; 32])
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(
                &rights_request
                    .signing_hash()
                    .map_err(|error| ProviderError::Provider(format!("{error:?}")))?,
            )
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte());
        let signed = WalletSignedRightsRequestV1::new(rights_request, signature_bytes)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let result = ProtectedContentRightsSignatureResultV1::new(
            account_id,
            wallet_address_hex(wallet(7)),
            hex::encode(signed.canonical_bytes().unwrap()),
        )
        .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let wallet_response = WalletProviderResponseV2::for_request(
            &wallet_request,
            WalletResultV2::Ok {
                data: serde_json::to_value(result)
                    .map_err(|error| ProviderError::Provider(error.to_string()))?,
            },
        );
        Ok(ok_provider_response(
            serde_json::to_value(wallet_response)
                .map_err(|error| ProviderError::Provider(error.to_string()))?,
        ))
    }
}

/// A managed-account wallet: the rights-signature request first lands as a
/// pending approval; only after `approve` does the exact same request replay
/// the Wallet's stored result inside its approval envelope (the shape the
/// real wallet-provider answers with).
struct ManagedReleaseWalletProvider {
    approved: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Requests the person has confirmed but whose signature has not come back
    /// yet. This is the real `approved` state an external wallet sits in
    /// between the person pressing Confirm and the connector posting the
    /// signature, and it answers `requires_approval: false` with no signed
    /// result -- the shape that once read as a hard failure.
    confirmed_awaiting_signature: std::sync::Mutex<std::collections::HashSet<String>>,
    seen: std::sync::Mutex<Vec<String>>,
}

impl ManagedReleaseWalletProvider {
    fn new() -> Self {
        Self {
            approved: std::sync::Mutex::new(std::collections::HashSet::new()),
            confirmed_awaiting_signature: std::sync::Mutex::new(std::collections::HashSet::new()),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn approve(&self, request_id: &str) {
        self.approved.lock().unwrap().insert(request_id.to_string());
    }

    /// The person has confirmed; the connector has not answered yet.
    fn confirm_awaiting_signature(&self, request_id: &str) {
        self.confirmed_awaiting_signature
            .lock()
            .unwrap()
            .insert(request_id.to_string());
    }

    fn seen_request_ids(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Provider for ManagedReleaseWalletProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "managed release wallet provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["wallet"]
    }

    fn name(&self) -> &'static str {
        "wallet"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let inner = request.get("request").cloned().ok_or_else(|| {
            ProviderError::Provider("wallet request is missing the v2 envelope".to_string())
        })?;
        let bytes = serde_json::to_vec(&inner)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let now = crate::auth::now_ts();
        let wallet_request = WalletProviderRequestV2::decode_at(&bytes, now)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        self.seen
            .lock()
            .unwrap()
            .push(wallet_request.request_id.clone());
        let awaiting_signature = self
            .confirmed_awaiting_signature
            .lock()
            .unwrap()
            .contains(&wallet_request.request_id);
        let approved = self
            .approved
            .lock()
            .unwrap()
            .contains(&wallet_request.request_id);
        let approval_request = json!({
            "schema": "elastos.wallet.approval_request/v1",
            "request_id": wallet_request.request_id,
            "intent": "protected_content_rights_signature",
            "status": if approved {
                "completed"
            } else if awaiting_signature {
                "approved"
            } else {
                "pending"
            },
            // The Wallet names the account the approval belongs to. A managed
            // account completes in place, so the open reports that nobody has
            // to go anywhere; an external one would carry its connector here.
            "proof_type": "managed_evm",
            "connector_id": Value::Null,
        });
        let data = if approved {
            let (account_id, canonical_rights_request_hex) = match &wallet_request.operation {
                WalletProviderOperationV2::RequestProtectedContentRightsSignature {
                    account_id,
                    canonical_rights_request_hex,
                    ..
                } => (account_id.clone(), canonical_rights_request_hex.clone()),
                _ => {
                    return Err(ProviderError::Provider(
                        "managed release wallet expected a protected-content rights signature"
                            .to_string(),
                    ));
                }
            };
            let rights_bytes = hex::decode(&canonical_rights_request_hex)
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let rights_request = RightsRequestV1::from_canonical_bytes(&rights_bytes)
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let key = WalletSigningKey::from_slice(&[7; 32])
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let (signature, recovery_id) = key
                .sign_prehash_recoverable(
                    &rights_request
                        .signing_hash()
                        .map_err(|error| ProviderError::Provider(format!("{error:?}")))?,
                )
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let mut signature_bytes = signature.to_bytes().to_vec();
            signature_bytes.push(recovery_id.to_byte());
            let signed = WalletSignedRightsRequestV1::new(rights_request, signature_bytes)
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let result = ProtectedContentRightsSignatureResultV1::new(
                account_id,
                wallet_address_hex(wallet(7)),
                hex::encode(signed.canonical_bytes().unwrap()),
            )
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
            json!({
                "approval_request": approval_request,
                "requires_approval": false,
                "signature": Value::Null,
                "signed_result": serde_json::to_value(result)
                    .map_err(|error| ProviderError::Provider(error.to_string()))?,
                "signature_receipt": { "request_id": wallet_request.request_id },
            })
        } else {
            json!({
                "approval_request": approval_request,
                // False once the person has confirmed, exactly as the real
                // wallet answers: `requires_approval` is `status == Pending`
                // alone, so the approved gap reports false with no signature.
                "requires_approval": !awaiting_signature,
                "signature": Value::Null,
            })
        };
        let wallet_response =
            WalletProviderResponseV2::for_request(&wallet_request, WalletResultV2::Ok { data });
        Ok(ok_provider_response(
            serde_json::to_value(wallet_response)
                .map_err(|error| ProviderError::Provider(error.to_string()))?,
        ))
    }
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
    let buy = super::reconstructed_buy_receipt(
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
    let session = super::derive_runtime_custody_session_binding(
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
    let invocation = || super::RuntimeReleaseWalletInvocation {
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
    let (request_bytes, approval_request_id) = match super::invoke_runtime_release_wallet(
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
        super::RuntimeReleaseWalletOutcome::PendingApproval {
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
        super::RuntimeReleaseWalletOutcome::Signed { .. } => panic!("expected pending approval"),
    };
    let decoded = WalletProviderRequestV2::decode_at(&request_bytes, now).unwrap();
    assert_eq!(approval_request_id, decoded.request_id);

    // Replaying the exact request before approval stays pending on the SAME
    // wallet request (no second approval is raised).
    match super::invoke_runtime_release_wallet(
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
        super::RuntimeReleaseWalletOutcome::PendingApproval {
            request_bytes: replayed,
            approval_request_id: replayed_id,
            ..
        } => {
            assert_eq!(replayed, request_bytes);
            assert_eq!(replayed_id, approval_request_id);
        }
        super::RuntimeReleaseWalletOutcome::Signed { .. } => panic!("expected pending approval"),
    }

    // A replay bound to a different recipient identity is refused: the
    // persisted request must belong to the prepared recipient being resumed.
    let foreign = super::invoke_runtime_release_wallet(
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
        super::RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE
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
    match super::invoke_runtime_release_wallet(
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
        super::RuntimeReleaseWalletOutcome::PendingApproval {
            request_bytes: replayed,
            approval_request_id: replayed_id,
            ..
        } => {
            // Still the same approval and the same request: the release waits
            // rather than raising a second one.
            assert_eq!(replayed, request_bytes);
            assert_eq!(replayed_id, approval_request_id);
        }
        super::RuntimeReleaseWalletOutcome::Signed { .. } => {
            panic!("a confirmed approval whose signature has not arrived is not signed")
        }
    }

    // Approved: the exact replay yields the signed rights for the SAME
    // request, decoded out of the Wallet's approval envelope.
    wallet.approve(&approval_request_id);
    let (signed_request_bytes, response_bytes, signed_rights) = signed_release_wallet_outcome(
        super::invoke_runtime_release_wallet(
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
    super::wallet_signed_rights_from_bytes(&signed_request_bytes, &response_bytes).unwrap();
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
pub(crate) fn write_device_key(data_dir: &Path, seed: u8) {
    let identity = data_dir.join("identity");
    fs::create_dir_all(&identity).unwrap();
    let path = identity.join("device.key");
    fs::write(&path, [seed; 32]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
fn derived_device_key_for_seed(seed: u8) -> (SigningKey, String) {
    elastos_identity::derive_did(&[seed; 32])
}

#[cfg(unix)]
fn derived_device_runtime_issuer(seed: u8) -> RuntimeOperationIssuerKeyV1 {
    let (key, _) = derived_device_key_for_seed(seed);
    RuntimeOperationIssuerKeyV1::new(key.verifying_key().to_bytes()).unwrap()
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_purchase_requires_current_verified_profile_authority() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-profile-check";
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let listing_path = super::runtime_listing_path(&harness.data_dir, mint.draft().mint_id());
    let listing_before = fs::read(&listing_path).unwrap();
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &derived_device_key_for_seed(0x27).1,
        crate::auth::now_ts(),
    );
    let purchase_path =
        super::runtime_purchase_path(&harness.data_dir, principal_id, mint.draft().mint_id());
    let purchase_json = String::from_utf8(fs::read(&purchase_path).unwrap()).unwrap();
    assert!(!purchase_json.contains("wallet_request_hex"));
    assert!(!purchase_json.contains("wallet_response_hex"));
    assert_eq!(fs::read(&listing_path).unwrap(), listing_before);
    let missing = super::load_runtime_custody_profile_did(&harness.data_dir, principal_id);
    assert!(missing.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_purchase_reconstruction_rejects_mismatched_profile_did() {
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
        &derived_device_key_for_seed(0x27).1,
        crate::auth::now_ts(),
    );
    let mismatch = super::reconstructed_buy_receipt(
        mint.draft(),
        &elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::from(
            mint.content_availability().unwrap().clone(),
        ),
        &purchase,
        &current_profile_did,
    );
    assert!(mismatch.is_err());
    assert!(mismatch
        .unwrap_err()
        .to_string()
        .contains("Runtime custody chain evidence is invalid"));
}

fn signed_release_wallet_outcome(
    outcome: super::RuntimeReleaseWalletOutcome,
) -> (Vec<u8>, Vec<u8>, WalletSignedRightsRequestV1) {
    match outcome {
        super::RuntimeReleaseWalletOutcome::Signed {
            request_bytes,
            response_bytes,
            signed_rights,
        } => (request_bytes, response_bytes, *signed_rights),
        super::RuntimeReleaseWalletOutcome::PendingApproval {
            approval_request_id,
            ..
        } => panic!("release wallet unexpectedly pending approval {approval_request_id}"),
    }
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
    let buy = super::reconstructed_buy_receipt(
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
    let session_a = super::derive_runtime_custody_session_binding(
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
    let session_b = super::derive_runtime_custody_session_binding(
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
    let launch_b = super::derive_runtime_custody_session_binding(
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
    let (request_a, response_a, signed_a) = super::invoke_runtime_release_wallet(
        registry.as_ref(),
        &buy,
        &recipient_identity(0x30),
        super::RuntimeReleaseWalletInvocation {
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

    let (request_b, _response_b, signed_b) = super::invoke_runtime_release_wallet(
        registry.as_ref(),
        &buy,
        &recipient_identity(0x30),
        super::RuntimeReleaseWalletInvocation {
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
    let open = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
        super::RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA
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
    let err = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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

    let error = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
    assert!(super::load_runtime_custody_viewer_record(
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
                super::load_runtime_custody_listing(&harness.data_dir, harness.mint_id)
                    .unwrap()
                    .unwrap();
            listing.package.price = "0x6".to_string();
            super::persist_runtime_custody_listing(&harness.data_dir, &listing).unwrap();
        } else {
            fs::remove_file(super::runtime_listing_path(
                &harness.data_dir,
                harness.mint_id,
            ))
            .unwrap();
        }
        let error = super::open_runtime_custody_viewer(
            &harness.data_dir,
            harness.registry.clone(),
            super::RuntimeCustodyViewerOpenInput {
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
    let early_segment = super::read_runtime_custody_viewer(
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
        Some(0),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        early_segment.to_string(),
        "Runtime custody viewer media part is invalid"
    );
    assert!(read_provider.requests().await.is_empty());
    let read = super::read_runtime_custody_viewer(
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
    let repeated_init = super::read_runtime_custody_viewer(
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
    let close = super::close_runtime_custody_viewer(
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
    let record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::Closed
    );
    let closed_record_bytes = fs::read(super::runtime_viewer_path(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    ))
    .unwrap();
    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();

    let replay = super::close_runtime_custody_viewer(
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
    let record_bytes = fs::read(super::runtime_viewer_path(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    ))
    .unwrap();
    assert_eq!(record_bytes, closed_record_bytes);
    let replay_record: super::RuntimeCustodyViewerRecord =
        serde_json::from_slice(&record_bytes).unwrap();
    assert_eq!(
        replay_record.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::Closed
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
        super::runtime_viewer_path(&harness.data_dir, principal_id, mint.draft().mint_id());
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

    let open_error = super::open_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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

    let read_error = super::read_runtime_custody_viewer(
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

    let error = super::close_runtime_custody_viewer(
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
    let err = super::close_runtime_custody_viewer(
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
    let pending = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        pending.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::CleanupPending
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
    super::reconcile_runtime_custody_viewers_after_decrypt_registration(
        &harness.data_dir,
        registry.clone(),
    )
    .await
    .unwrap();
    let settled = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        settled.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
    );
    assert_eq!(absent_provider.requests().await.len(), 1);
    assert_exact_runtime_decrypt_invocation(
        &absent_provider.requests().await[0],
        "close_viewer_session",
        &serde_json::to_value(&close_request).unwrap(),
    );
    assert!(!harness
        .data_dir
        .join(super::RUNTIME_MINT_JOURNAL_ROOT)
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

    let listing = super::load_runtime_custody_listing(&harness.data_dir, mint.draft().mint_id())
        .unwrap()
        .unwrap();
    let settled = super::settle_runtime_custody_viewer_cleanup(
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
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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
    let persisted = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        persisted.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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

    let listing = super::load_runtime_custody_listing(&harness.data_dir, mint.draft().mint_id())
        .unwrap()
        .unwrap();
    let settled = super::settle_runtime_custody_viewer_cleanup(
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
        super::RuntimeCustodyViewerLifecycleStatus::Closed
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
    let persisted = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        persisted.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::Closed
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
    let before = fs::read(super::runtime_viewer_path(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    ))
    .unwrap();
    let active = super::RuntimeCustodyViewerRecord::from_active_session(
        principal_id,
        &current_profile_did,
        mint.draft().mint_id(),
        &purchase.content_id,
        super::derive_runtime_custody_session_binding(
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
        super::runtime_viewer_path(&harness.data_dir, principal_id, mint.draft().mint_id())
            .parent()
            .unwrap()
            .to_path_buf();
    fs::set_permissions(&viewers_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let persist_error = super::persist_runtime_custody_viewer_record(
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
    let listing = super::load_runtime_custody_listing(&harness.data_dir, mint.draft().mint_id())
        .unwrap()
        .unwrap();
    let cleanup_error = super::settle_runtime_custody_viewer_cleanup(
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
        fs::read(super::runtime_viewer_path(
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
    let err = super::read_runtime_custody_viewer(
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
    let record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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

    super::reconcile_runtime_custody_viewers_after_decrypt_registration(
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
    let record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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
        super::runtime_viewer_path(&harness.data_dir, principal_id, mint.draft().mint_id());
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

    let read_error = super::read_runtime_custody_viewer(
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

    let close_error = super::close_runtime_custody_viewer(
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
        super::runtime_viewer_path(&harness.data_dir, principal_id, mint.draft().mint_id());
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

    let read_error = super::read_runtime_custody_viewer(
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

    let close_error = super::close_runtime_custody_viewer(
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

    super::reconcile_runtime_custody_viewers_after_decrypt_registration(
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
    let record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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
    let mut record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    record.mark_cleanup_pending(crate::auth::now_ts());
    super::persist_runtime_custody_viewer_record(
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

    super::reconcile_runtime_custody_viewers_after_decrypt_registration(
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
    let settled = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        settled.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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

    let error = super::open_runtime_custody_viewer(
        &harness.data_dir,
        registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
    let record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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
        let mut record = super::RuntimeCustodyViewerRecord::from_active_session(
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
        super::persist_runtime_custody_viewer_record(
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

    super::reconcile_runtime_custody_viewers_after_decrypt_registration(
        &harness.data_dir,
        registry,
    )
    .await
    .unwrap();

    let record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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
    let mut record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    record.viewer_session_handle = hex::encode([0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]);
    super::persist_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();

    let error = super::reconcile_runtime_custody_viewers_after_decrypt_registration(
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

    super::reconcile_runtime_custody_viewers_after_decrypt_boot(&harness.data_dir, registry).await;

    let record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        record.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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
    let mut record = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    record.viewer_session_handle = hex::encode([0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]);
    super::persist_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();

    super::reconcile_runtime_custody_viewers_after_decrypt_boot(
        &harness.data_dir,
        Arc::new(ProviderRegistry::new()),
    )
    .await;

    let persisted = super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        persisted.lifecycle_status,
        super::RuntimeCustodyViewerLifecycleStatus::Active
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
        let _guard = super::acquire_runtime_custody_viewer_lifecycle_guard(
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
        let _guard = super::acquire_runtime_custody_viewer_lifecycle_guard(
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
        let _guard = super::acquire_runtime_custody_viewer_lifecycle_guard(
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
    let open = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
    assert!(super::load_runtime_custody_viewer_record(
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
    let open = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
    assert!(super::load_runtime_custody_viewer_record(
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
    let open = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
            .contains(super::RUNTIME_CUSTODY_ELSEWHERE_MESSAGE),
        "{open}"
    );
    assert!(super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
}

#[cfg(unix)]
fn process_custody_play_routes(
    epoch: &SignedCustodyEpochV1,
    owner_state_roots: [Digest32; 3],
) -> Vec<RuntimeCustodyRouteBindingConfig> {
    epoch
        .statement()
        .nodes()
        .iter()
        .zip(owner_state_roots)
        .zip([
            RuntimeCustodyRouteTransportConfig::Local,
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_for_seed(0xa1),
            },
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_for_seed(0xa2),
            },
        ])
        .map(
            |((node, owner_state_root), transport)| RuntimeCustodyRouteBindingConfig {
                node_public_key_base64: raw_b64_32(*node.node_public_key().as_bytes()),
                owner_state_root_base64: raw_b64_32(*owner_state_root.as_bytes()),
                transport,
            },
        )
        .collect()
}

#[cfg(unix)]
async fn register_test_decrypt_provider(
    registry: &Arc<ProviderRegistry>,
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
) {
    let decrypt_binary = required_test_binary_path(TEST_DECRYPT_PROVIDER_BIN_ENV);
    register_protected_content_decrypt_provider(
        registry,
        &decrypt_binary,
        runtime_operation_issuer,
    )
    .await
    .unwrap();
}

#[cfg(unix)]
pub(crate) struct RuntimeCustodyProcessProviderFixture {
    _nodes_temp: tempfile::TempDir,
    nodes: Vec<(NodePublicKey, Arc<ProviderRegistry>)>,
    composition: RuntimeCustodyCompositionConfigFile,
}

#[cfg(unix)]
/// The clear media the gateway tests' mock media provider prepares: per
/// rendition (video, then audio) its init and its segments.
#[allow(clippy::type_complexity)]
pub(crate) fn runtime_custody_gateway_media_output_for_test(
) -> Vec<(CencDashRenditionKindV2, Vec<u8>, Vec<Vec<u8>>)> {
    media_dash_fixture::clear_media_dash(
        &[TEST_PREPARED_VIDEO.kind, TEST_PREPARED_AUDIO.kind],
        &[TEST_PREPARED_VIDEO.segments, TEST_PREPARED_AUDIO.segments],
    )
}

/// The parts a v2 viewer reads, in the interleave `read_viewer` walks: every
/// init in rendition order, then for each segment index the segment of every
/// rendition. Per part `(rendition, segment index or None for an init, the
/// clear bytes it must decrypt to)`.
#[allow(clippy::type_complexity)]
pub(crate) fn runtime_custody_gateway_media_parts_for_test() -> Vec<(u8, Option<u32>, Vec<u8>)> {
    let media = runtime_custody_gateway_media_output_for_test();
    let mut parts = Vec::new();
    for (rendition, (_, init, _)) in media.iter().enumerate() {
        parts.push((rendition as u8, None, init.clone()));
    }
    let longest = media
        .iter()
        .map(|(_, _, segments)| segments.len())
        .max()
        .unwrap_or(0);
    for index in 0..longest {
        for (rendition, (_, _, segments)) in media.iter().enumerate() {
            if let Some(segment) = segments.get(index) {
                parts.push((rendition as u8, Some(index as u32), segment.clone()));
            }
        }
    }
    parts
}

#[cfg(unix)]
pub(crate) async fn register_runtime_custody_process_providers_for_test_registry(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
) -> RuntimeCustodyProcessProviderFixture {
    let protect_binary = required_test_binary_path(TEST_PROTECT_PROVIDER_BIN_ENV);
    let custody_binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let nodes_temp = tempfile::tempdir().unwrap();
    let nodes_root = fs::canonicalize(nodes_temp.path()).unwrap();
    owner_only_dir(data_dir);
    let (runtime_device_key, _) = elastos_identity::load_or_create_did(data_dir).unwrap();
    let runtime_issuer =
        RuntimeOperationIssuerKeyV1::new(runtime_device_key.verifying_key().to_bytes()).unwrap();
    let node1 = provisioned_process_custody_node_for_issuer(
        &custody_binary,
        &nodes_root,
        "node-1",
        runtime_issuer,
        digest(0xa1),
    );
    let node2 = provisioned_process_custody_node_for_issuer(
        &custody_binary,
        &nodes_root,
        "node-2",
        runtime_issuer,
        digest(0xa2),
    );
    let node3 = provisioned_process_custody_node_for_issuer(
        &custody_binary,
        &nodes_root,
        "node-3",
        runtime_issuer,
        digest(0xa3),
    );
    for fixture in [&node1, &node2, &node3] {
        fixture
            .registry
            .register_sub_provider(
                CHAIN_PROVIDER_ID,
                Arc::new(AllowingProcessChainEvidenceProvider),
            )
            .await
            .unwrap();
    }
    crate::host_trust::seed_wci_host_for_test(&nodes_root.join("node-1"));
    register_custody_provider(&node1.registry, &custody_binary, &nodes_root.join("node-1"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&nodes_root.join("node-2"));
    register_custody_provider(&node2.registry, &custody_binary, &nodes_root.join("node-2"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&nodes_root.join("node-3"));
    register_custody_provider(&node3.registry, &custody_binary, &nodes_root.join("node-3"))
        .await
        .unwrap();

    let epoch = signed_custody_epoch_for_node_keys([
        (
            node1.provisioned.node_public_key,
            node1.provisioned.node_custody_public_key,
        ),
        (
            node2.provisioned.node_public_key,
            node2.provisioned.node_custody_public_key,
        ),
        (
            node3.provisioned.node_public_key,
            node3.provisioned.node_custody_public_key,
        ),
    ]);
    let fixtures_by_node = BTreeMap::from([
        (node1.provisioned.node_public_key, node1),
        (node2.provisioned.node_public_key, node2),
        (node3.provisioned.node_public_key, node3),
    ]);
    let ordered_fixtures = epoch
        .statement()
        .nodes()
        .iter()
        .map(|node| fixtures_by_node.get(&node.node_public_key()).unwrap())
        .collect::<Vec<_>>();
    let owner_state_roots = [
        ordered_fixtures[0].owner_state_root,
        ordered_fixtures[1].owner_state_root,
        ordered_fixtures[2].owner_state_root,
    ];
    let now = crate::auth::now_ts();
    let pool = signed_custody_pool_for_epoch(&epoch, (now.saturating_sub(60), now + 3_600));
    let authorization =
        signed_committee_authorization_for_epoch(pool.pool_identity().unwrap(), &epoch);
    let composition = RuntimeCustodyCompositionConfigFile {
        schema: CUSTODY_COMPOSITION_SCHEMA_V1.to_string(),
        expected_policy_authority_base64: raw_b64_32(
            SigningKey::from_bytes(&[0x71; 32])
                .verifying_key()
                .to_bytes(),
        ),
        expected_committee_authorization_identity_base64: canonical_b64(
            &authorization.authorization_identity().unwrap(),
        ),
        signed_pool_base64: canonical_b64(&pool),
        signed_epoch_base64: canonical_b64(&epoch),
        signed_committee_authorization_base64: canonical_b64(&authorization),
        routes: process_custody_play_routes(&epoch, owner_state_roots),
    };
    write_owner_only_custody_composition_config(data_dir, &composition);
    let nodes = ordered_fixtures
        .iter()
        .map(|fixture| {
            (
                fixture.provisioned.node_public_key,
                fixture.registry.clone(),
            )
        })
        .collect::<Vec<_>>();

    register_protect_provider(registry, &protect_binary)
        .await
        .unwrap();
    registry
        .register_runtime_provider_target(
            CUSTODY_PROVIDER_ID,
            Arc::new(LibraryProcessCustodyDispatcher {
                expected_issuer: runtime_issuer,
                nodes: nodes.clone(),
            }),
        )
        .await
        .unwrap();
    registry
        .set_carrier_invoker(Arc::new(LoopbackCustodyCarrierInvoker {
            registry: Arc::downgrade(registry),
        }))
        .await;
    register_test_decrypt_provider(registry, runtime_issuer).await;
    RuntimeCustodyProcessProviderFixture {
        _nodes_temp: nodes_temp,
        nodes,
        composition,
    }
}

#[cfg(unix)]
pub(crate) async fn attach_runtime_custody_process_providers_for_buyer_runtime(
    fixture: &RuntimeCustodyProcessProviderFixture,
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
) {
    owner_only_dir(data_dir);
    write_owner_only_custody_composition_config(data_dir, &fixture.composition);
    let (runtime_device_key, _) = elastos_identity::load_or_create_did(data_dir).unwrap();
    let runtime_issuer =
        RuntimeOperationIssuerKeyV1::new(runtime_device_key.verifying_key().to_bytes()).unwrap();
    registry
        .register_runtime_provider_target(
            CUSTODY_PROVIDER_ID,
            Arc::new(LibraryProcessCustodyDispatcher {
                expected_issuer: runtime_issuer,
                nodes: fixture.nodes.clone(),
            }),
        )
        .await
        .unwrap();
    registry
        .set_carrier_invoker(Arc::new(LoopbackCustodyCarrierInvoker {
            registry: Arc::downgrade(registry),
        }))
        .await;
    register_test_decrypt_provider(registry, runtime_issuer).await;
}

/// Make `fixture`'s pool the custody composition this Home runs, as a Home
/// whose pool changed between two presses would.
#[cfg(unix)]
pub(crate) fn install_runtime_custody_composition_for_test(
    fixture: &RuntimeCustodyProcessProviderFixture,
    data_dir: &Path,
) {
    write_owner_only_custody_composition_config(data_dir, &fixture.composition);
}

#[cfg(unix)]
pub(crate) fn assert_no_unresolved_runtime_custody_release_for_test(data_dir: &Path) {
    let release_root = data_dir.join("protected-content/runtime-release");
    assert!(list_unresolved_runtime_releases(&release_root)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&release_root)
        .unwrap()
        .is_empty());
}

#[cfg(unix)]
pub(crate) async fn register_runtime_custody_mock_media_provider_for_test_registry(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
) {
    register_runtime_custody_mock_media_provider_rendition(
        data_dir,
        registry,
        TestMediaPreparationResponse::prepared_video_audio(),
    )
    .await;
}

#[cfg(unix)]
pub(crate) async fn register_runtime_custody_mock_audio_media_provider_for_test_registry(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
) {
    register_runtime_custody_mock_media_provider_rendition(
        data_dir,
        registry,
        TestMediaPreparationResponse::prepared_audio(),
    )
    .await;
}

#[cfg(unix)]
async fn register_runtime_custody_mock_media_provider_rendition(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    response: TestMediaPreparationResponse,
) {
    let provider_root = data_dir.join("protected-content/media-provider");
    owner_only_dir(&provider_root);
    let staging_root = provider_root.join("staging");
    owner_only_dir(&staging_root);
    registry
        .register_runtime_provider_target(
            MEDIA_PROVIDER_ID,
            Arc::new(TestMediaPreparationProvider {
                staging_root,
                requests: Mutex::new(Vec::new()),
                response,
            }),
        )
        .await
        .unwrap();
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
    let open = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
    assert!(super::load_runtime_custody_viewer_record(
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
    let open = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
    let record = super::load_runtime_custody_viewer_record(
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
        super::RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
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
    let open = super::open_runtime_custody_viewer(
        &harness.data_dir,
        harness.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
    assert!(super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
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

fn test_object_identity(framed_bytes: &[u8]) -> ChunkedPayloadObjectIdentityV1 {
    let ciphertext_sha256 = Digest32::new(sha2::Sha256::digest(framed_bytes).into());
    let encrypted_content =
        EncryptedContentIdentityV1::new(ciphertext_sha256, framed_bytes.len() as u64).unwrap();
    ChunkedPayloadObjectIdentityV1::new(encrypted_content, "application/pdf", 4096, 64).unwrap()
}

fn write_object_protected_content_directory(
    directory: &Path,
    object_identity: &ChunkedPayloadObjectIdentityV1,
    framed_bytes: &[u8],
) {
    let tree = directory.join("protected-content/v1");
    fs::create_dir_all(&tree).unwrap();
    fs::write(
        directory.join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
        protected_content_object_manifest_bytes(object_identity).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join(PROTECTED_CONTENT_OBJECT_EPC1_PATH),
        framed_bytes,
    )
    .unwrap();
}

#[test]
fn publish_object_seals_with_epc1_and_writes_object_manifest() {
    let framed_bytes = vec![0x5au8; 4160];
    let object_identity = test_object_identity(&framed_bytes);
    let directory = tempfile::tempdir().unwrap();
    write_object_protected_content_directory(directory.path(), &object_identity, &framed_bytes);

    verify_protected_content_object_directory(directory.path(), &object_identity)
        .expect("a freshly written object directory must verify");

    let files = object_protected_content_files(&object_identity).unwrap();
    assert_eq!(files.len(), 2);
    assert!(files
        .iter()
        .any(|file| file.path == PROTECTED_CONTENT_OBJECT_EPC1_PATH
            && file.size == framed_bytes.len() as u64
            && file.sha256
                == hex::encode(
                    object_identity
                        .encrypted_content()
                        .ciphertext_sha256()
                        .as_bytes()
                )));
    assert!(files
        .iter()
        .any(|file| file.path == PROTECTED_CONTENT_OBJECT_MANIFEST_PATH));

    let manifest_bytes = fs::read(
        directory
            .path()
            .join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
    )
    .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(
        manifest["schema"],
        "elastos.protected-content.object-manifest/v1"
    );
    assert_eq!(manifest["content_type"], "application/pdf");
    assert_eq!(manifest["plaintext_bytes"], 4096);
    assert_eq!(manifest["framed_header_bytes"], 64);
    assert_eq!(
        manifest["encrypted_content"]["sha256"],
        hex::encode(
            object_identity
                .encrypted_content()
                .ciphertext_sha256()
                .as_bytes()
        )
    );
    assert_eq!(manifest["encrypted_content"]["bytes"], 4160);
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
fn object_directory_verify_streams_a_large_file() {
    use std::io::{Seek, SeekFrom, Write};
    let directory = tempfile::tempdir().unwrap();
    let tree = directory.path().join("protected-content/v1");
    fs::create_dir_all(&tree).unwrap();
    let epc1 = directory.path().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH);
    let length = 80 * 1024 * 1024u64;
    let mut file = fs::File::create(&epc1).unwrap();
    file.set_len(length).unwrap();
    for offset in [0u64, 1 << 20, 40 << 20] {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[0xa5; 4096]).unwrap();
    }
    drop(file);
    let (sha, bytes) = sha256_file(&epc1).unwrap();
    assert_eq!(bytes, length);
    let identity = ChunkedPayloadObjectIdentityV1::new(
        EncryptedContentIdentityV1::new(sha, length).unwrap(),
        "application/pdf",
        length - 64,
        64,
    )
    .unwrap();
    fs::write(
        directory
            .path()
            .join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
        protected_content_object_manifest_bytes(&identity).unwrap(),
    )
    .unwrap();
    verify_protected_content_object_directory(directory.path(), &identity).unwrap();

    let mut file = fs::OpenOptions::new().write(true).open(&epc1).unwrap();
    file.seek(SeekFrom::Start(75 << 20)).unwrap();
    file.write_all(&[0x01]).unwrap();
    drop(file);
    assert!(verify_protected_content_object_directory(directory.path(), &identity).is_err());
}

#[test]
fn object_framed_staging_sink_hashes_what_it_writes() {
    #[derive(Default)]
    struct CountingWriter {
        total: u64,
        largest_write: usize,
        written: Vec<u8>,
    }
    impl std::io::Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.total += buffer.len() as u64;
            self.largest_write = self.largest_write.max(buffer.len());
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let header = vec![0x01u8; 64];
    let mut expected = header.clone();
    let mut sink = ObjectFramedStagingSink::new(CountingWriter::default());
    sink.push(&header).unwrap();
    for index in 0..70u8 {
        let piece = vec![index; MAX_OBJECT_FRAMED_CHUNK_BYTES_V1];
        expected.extend_from_slice(&piece);
        sink.push(&piece).unwrap();
    }
    let (identity, writer) = sink.finish().unwrap();
    assert_eq!(writer.total, expected.len() as u64);
    assert_eq!(identity.ciphertext_bytes(), expected.len() as u64);
    assert_eq!(
        identity.ciphertext_sha256(),
        Digest32::new(sha2::Sha256::digest(&expected).into())
    );
    assert!(writer.largest_write <= MAX_OBJECT_FRAMED_CHUNK_BYTES_V1);
}

#[test]
fn verify_protected_content_directory_rejects_tampered_object_file() {
    let framed_bytes = vec![0x5au8; 4160];
    let object_identity = test_object_identity(&framed_bytes);
    let directory = tempfile::tempdir().unwrap();
    write_object_protected_content_directory(directory.path(), &object_identity, &framed_bytes);
    verify_protected_content_object_directory(directory.path(), &object_identity).unwrap();

    // Tamper with the framed ciphertext after the fact: the sha256 no longer
    // matches what the object identity commits to.
    let mut tampered = framed_bytes.clone();
    tampered[0] ^= 0xff;
    fs::write(
        directory.path().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH),
        &tampered,
    )
    .unwrap();
    assert!(verify_protected_content_object_directory(directory.path(), &object_identity).is_err());

    // Restore, then tamper with the manifest instead.
    fs::write(
        directory.path().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH),
        &framed_bytes,
    )
    .unwrap();
    fs::write(
        directory.path().join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
        br#"{"schema":"elastos.protected-content.object-manifest/v1","content_type":"text/plain","plaintext_bytes":4096,"framed_header_bytes":64,"encrypted_content":{"sha256":"00","bytes":4160}}"#,
    )
    .unwrap();
    assert!(verify_protected_content_object_directory(directory.path(), &object_identity).is_err());

    // A directory missing the object entirely must also fail closed.
    let empty = tempfile::tempdir().unwrap();
    assert!(verify_protected_content_object_directory(empty.path(), &object_identity).is_err());
}

/// A byte-for-byte copy of a real listing file written by the installed
/// Runtime *before* the object widening landed, taken from this machine's
/// installed data directory
/// (`~/Library/Application Support/elastos/protected-content/runtime-listings/
/// 58a70fb16023b740402f180b162fa6683fd9b2d21d9a6c8955e801c0be0e7b3d.json`,
/// stamped 2026-09-06 by the installed end-to-end proof run; one of the 14
/// listings that corpus holds, every one of them carrying
/// `media_identity_base64`).
///
/// It was deliberately NOT regenerated by the current encoder: a fixture the
/// new code can produce proves nothing about the listings already on disk.
const REAL_PRE_OBJECT_WIDENING_LISTING_JSON: &[u8] = br#"{"schema":"elastos.library.runtime-custody-listing/v1","origin":{"kind":"local_creator","principal_id":"person:local:b62d976e8b765ee6819e585a6fc69486","listing_uri":"elastos://Qmf4jPsuwJtF4YBBX3LUFpp8Kxqc2LyrFoGtLqes4q7xuf","package_sha256":"81a3de84abe41219508112d5def9a6d82869df653b2be1a7231af65538626716"},"package":{"schema":"elastos.protected-content.portable-listing/v1","mint_id":"58a70fb16023b740402f180b162fa6683fd9b2d21d9a6c8955e801c0be0e7b3d","content_id":"content:5adec06aa185a801d88e440e0054503d2a7c9ff59ad3f999e2b36c5253c99f56","content_cid":"QmUgzoEcj1MtBzCJ4tQxMYJVpMKkjro1pn8Eom43ZSJNtX","metadata_cid":"QmX1bpSqJeXdSQ3gj1yYbazp9zD3EXR3tEtAkCVAgCXunr","token_uri":"ipfs://QmX1bpSqJeXdSQ3gj1yYbazp9zD3EXR3tEtAkCVAgCXunr/metadata.json","publisher_profile_did":"did:key:z6MkgowPpYJhdHT4E6xQcs1PBxvF2YYFuJLdcgcDaWMHoR9Q","display_name":"protected-content-installed-e2e-proof-20260906T071856Z-7576","media_identity_base64":"ZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5jZW5jLWZtcDQtbWVkaWEtaWRlbnRpdHkvdjEAABZjZW5jLWZtcDQtYWVzMTI4Y3RyL3YxAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmVuY3J5cHRlZC1jb250ZW50L3YxACqs+NINPwTniTCHRJp8YEROnvoMMv7cerqTaXxc+EwSAAAAAAABn0vu0fVUIOwTa7f1hALcHFc+gwPUhxdKL+Eld7jnWLGOU8MP6bfu3Mgl5C+MJS0cNdXlouB4LkteryHNEfX6rtm0AAAAAAAAA4MACXZpZGVvL21wNAALYXZjMS42NDAwMjgAAwBXZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5jZW5jLWZtcDQtc2VnbWVudC92MQCmaDmlEUShdbHpbVD037JOdUoqKQjwh3L3VupHy9r2yQAAAAAAAJBdAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmNlbmMtZm1wNC1zZWdtZW50L3YxAEGyspD4GIRJ/oRHjxW1IewpWpy6woVnkFr0G7C+/M9mAAAAAAAAljoAV2VsYXN0b3MucHJvdGVjdGVkLWNvbnRlbnQuY2VuYy1mbXA0LXNlZ21lbnQvdjEAphAM2eZLmC4ciOkcomIjkHCYFen6NE7mhx1ra4A3IrsAAAAAAAB4tA==","content_access_id":"0xd3b75643e2d735d466ba1ceb9aa76e44","key_envelope_identity_base64":"ZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5rZXktZW52ZWxvcGUvdjEAAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmVuY3J5cHRlZC1jb250ZW50L3YxACqs+NINPwTniTCHRJp8YEROnvoMMv7cerqTaXxc+EwSAAAAAAABn0vNRf5pRtXoOz7TAPK1u4TyTdsCC9XxAEEGNC8YI76HHQAAH8EBwgwcBjXemQvazqEIu6nuwvChPMLXqatgtjYJWW3XmgIDAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmN1c3RvZHktcG9vbC5pZGVudGl0eS92MQCEOT8R2alUlpWVxgx3n9AS2pd6Ok8Xppb5AWQ+TAKDwgAAFK0AWGVsYXN0b3MucHJvdGVjdGVkLWNvbnRlbnQuY3VzdG9keS1lcG9jaC1pZGVudGl0eS92MQDn9SGB0cbTUlbSJwL9jB1X9Ge3vt5uCZBvY4bfFosrLwAAENcAamVsYXN0b3MucHJvdGVjdGVkLWNvbnRlbnQuY3VzdG9keS1jb21taXR0ZWUtYXV0aG9yaXphdGlvbi5pZGVudGl0eS92MQCCGGc5r/gwRtJY1Co5gfdxiXLXPMEVH3Gbp4JIKRy6/AAAAaI=","rights_policy_identity_base64":"ZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5yaWdodHMtcG9saWN5LWlkZW50aXR5L3YxABFFBT9Njh7IiiewWpDprkfdHefJL9J/JB/86JXUFDjjAAAA+A==","content_key_commitment_base64":"kSNx+7wd8YimGT4pxpELj2cjeCYachPFmv4uCClpiV4=","seller_address":"0xf36c114c19f96b4174b6d71e392c00db95093a1e","chain_namespace":"eip155:8453","network":"base-mainnet","ledger":"0x0ebac909d31ef0074495e752c0cf4ea49ba13c41","token_id":"0xeaa1578cfda2c9885e4f626cf014c2d42c6be5c71ce64ebc9bda704072b32556","operative":"0xbaec8aa7dbbe6ef205feb93cb83a2bf91d650098","quantity":"0x3","price":"0x38d7ea4c68000","pay_token":"0x0000000000000000000000000000000000000000","mint_transaction_hash":"0xb8f5b500e32c54470ba5b674108da44ec74b3a4c4612b5bbc61cf3b2a85c89d9","published_at":1788679217},"availability":{"checked_at":1788679139,"observed_replicas":3,"receipt_digest":"85811f14bde02cac0498daff517c46f5ddaeb7a539bbe5756d5c6c948eb6aedc"}}"#;

/// The `package_sha256` the real file above already carries, pinned as a
/// literal. `RuntimeCustodyListingRecord::validate` recomputes
/// `sha256(serde_json::to_vec(package))` and compares it to the value stored
/// in the record's own `origin`, so a single changed byte in a media
/// package's re-serialization fails the whole record — this literal makes
/// that pin visible rather than implicit.
const REAL_PRE_OBJECT_WIDENING_PACKAGE_SHA256: &str =
    "81a3de84abe41219508112d5def9a6d82869df653b2be1a7231af65538626716";

#[test]
fn real_pre_object_widening_listing_still_decodes_and_reserializes_byte_identically() {
    let record: super::RuntimeCustodyListingRecord =
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

/// Validation reads the accepted floor and new mints ask for the target. The
/// floor stays at one copy, and the target never goes below it.
#[test]
fn accepted_floor_never_exceeds_new_mint_target() {
    let floor = super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR;
    let target = super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET;
    assert_eq!(floor, 1, "a listing verified with one copy stays valid");
    assert_ne!(
        floor.cmp(&target),
        std::cmp::Ordering::Greater,
        "a new mint asks for at least the copies a listing must keep"
    );
    assert_eq!(
        super::protected_content_live_proof_required(target),
        target > 1,
        "a new mint asks for a live proof only when it asks for another copy"
    );
    assert_eq!(
        super::protected_content_live_proof_required(floor),
        floor > 1,
        "a re-check at the floor asks for a live proof only when the floor needs another copy"
    );
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
                super::PROTECTED_CONTENT_REPLICATION_POLICY,
                minimum_replicas,
                super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
                super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
            )
            .unwrap()
        };
        let recheck = requirement_for(super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR);
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
        let receipt = super::fetch_content_availability_receipt(&registry, &content_cid)
            .await
            .unwrap();
        let manifest = crate::content::fetch_content_object_manifest(&registry, &content_cid)
            .await
            .unwrap();
        let check = |requirement: &RuntimeContentAvailabilityRequirement| {
            super::verify_protected_content_receipt(
                &content_cid,
                &manifest,
                &receipt,
                &media,
                requirement,
                NOW,
                super::RuntimeManifestPublisherBinding::Exact,
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
    let mut record: super::RuntimeCustodyListingRecord =
        serde_json::from_slice(REAL_PRE_OBJECT_WIDENING_LISTING_JSON).unwrap();
    record.availability.observed_replicas = ONE_COPY;
    record
        .validate()
        .expect("a listing verified with one copy stays valid");
    assert_eq!(
        super::runtime_custody_listing_availability(&record)["required_replicas"],
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
        super::PROTECTED_CONTENT_REPLICATION_POLICY,
        super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .unwrap();
    assert_eq!(recheck.minimum_replicas(), ONE_COPY);
    super::validate_protected_content_availability_requirement(&recheck)
        .expect("a one-copy re-check requirement is accepted");
}

/// A deterministic object mint draft plus the portable listing package a
/// creator would publish for it: the object twin of
/// `runtime_custody_listing_record_for_test`'s media package, reusing every
/// non-identity field verbatim so the only difference under test is which
/// identity field the package carries.
fn object_listing_package_for_test(
    seed: u8,
) -> (
    ChunkedPayloadObjectIdentityV1,
    super::RuntimePortableListingPackage,
) {
    let epoch = signed_custody_epoch();
    let framed = vec![seed; 4160];
    let object_identity = ChunkedPayloadObjectIdentityV1::new(
        EncryptedContentIdentityV1::new(
            Digest32::new(sha2::Sha256::digest(&framed).into()),
            framed.len() as u64,
        )
        .unwrap(),
        "application/pdf",
        4096,
        64,
    )
    .unwrap();
    let manifest = CustodyEnvelopeManifestV1::new(
        object_identity.encrypted_content().clone(),
        CustodyPoolIdentityV1::new(digest(seed ^ 0x34), 512).unwrap(),
        epoch.epoch_identity().unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(seed ^ 0x35), 512).unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        digest(seed ^ 0x33),
        epoch.statement().nodes().to_vec(),
    )
    .unwrap();
    let envelope = CustodyEnvelopeV1::new(
        manifest,
        [seed ^ 0x50, seed ^ 0x51, seed ^ 0x52]
            .into_iter()
            .map(sealed_share)
            .collect(),
    )
    .unwrap();
    let mint_nodes = epoch
        .statement()
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let node_seed = u8::try_from(index + 1).unwrap();
            RuntimeMintNodeBinding::new(
                node.node_public_key(),
                CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
                Digest32::new([0x3f + node_seed; 32]),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::Object(object_identity.clone()),
        content_access_id(seed),
        envelope.key_envelope_identity().unwrap(),
        policy_body().policy_identity().unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        mint_nodes,
    )
    .unwrap();
    let media_package = runtime_custody_listing_record_for_test(
        draft.mint_id(),
        "person:local:object-listing",
        "object-listing",
        NOW,
    )
    .package;
    let (media_identity_base64, content_identity_base64) =
        super::runtime_portable_identity_fields(draft.content_identity()).unwrap();
    let package = super::RuntimePortableListingPackage {
        mint_id: hex::encode(draft.mint_id().as_bytes()),
        content_id: super::runtime_protected_content_id(draft.encrypted_content()).unwrap(),
        content_access_id: format!("0x{}", hex::encode(draft.content_access_id().as_bytes())),
        media_identity_base64,
        content_identity_base64,
        key_envelope_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.key_envelope().canonical_bytes().unwrap()),
        rights_policy_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.policy().canonical_bytes().unwrap()),
        content_key_commitment_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.content_key_commitment().as_bytes()),
        ..media_package
    };
    (object_identity, package)
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
        serde_json::from_slice::<super::RuntimePortableListingPackage>(&bytes).unwrap(),
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
        super::runtime_portable_content_codecs(&decoded.content_identity),
        "",
        "an object declares no codecs"
    );
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
        super::runtime_custody_object_framed_header(&framed, &object_identity).unwrap(),
        framed_header
    );
    for (index, expected) in framed_chunks.iter().enumerate() {
        assert_eq!(
            &super::runtime_custody_object_framed_chunk(
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
    assert!(super::runtime_custody_object_framed_chunk(&framed, &object_identity, 3).is_err());
    assert!(
        super::runtime_custody_object_framed_chunk(&framed, &object_identity, u32::MAX).is_err()
    );
    // A truncated file cannot yield a chunk either.
    let truncated = framed[..framed.len() - 1].to_vec();
    assert!(super::runtime_custody_object_framed_chunk(&truncated, &object_identity, 2).is_err());
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
    let binding = super::derive_runtime_custody_session_binding(
        "person:local:object-reader",
        "did:key:zObjectReader",
        super::ELACITY_READER_CAPSULE_ID,
        TEST_VIEWER_LAUNCH_ID,
        "proof:object",
        "runtime-session:object",
        "grant:object",
        digest(0x31),
    )
    .unwrap();
    let mut record = super::RuntimeCustodyViewerRecord::from_open_pending(
        super::RuntimeCustodyOpenPendingInput {
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

/// The codes the custody capsule emits only from paths that precede its
/// durable write. Everything else — `backend_unavailable` above all, which the
/// capsule returns both for a refusal before the write and for a failure after
/// it — must stay uncertain.
#[test]
fn custody_refusal_codes_claim_no_effect_only_where_the_capsule_proves_it() {
    for code in [
        "invalid_request",
        "provisioning_refused",
        "rights_denied",
        "operation_expired",
        "evidence_expired",
    ] {
        assert_eq!(
            super::classify_custody_failure(
                "release_contribution",
                &super::ProviderInvocationFailure::Refused {
                    code: code.to_string(),
                    message: "refused".to_string(),
                },
            ),
            RuntimeProviderCallError::RefusedWithoutEffect,
            "{code} is emitted only before the durable write"
        );
    }
    for code in ["backend_unavailable", "invalid_config", "unknown", ""] {
        // `backend_unavailable` is the one that matters here: the capsule
        // returns it both for a refusal before the write and for a failure
        // after it.
        assert_eq!(
            super::classify_custody_failure(
                "provision_node_share",
                &super::ProviderInvocationFailure::Refused {
                    code: code.to_string(),
                    message: "refused".to_string(),
                },
            ),
            RuntimeProviderCallError::NoExactResult,
            "{code} spans acted and did-not-act paths"
        );
    }
}

/// A custody refusal keeps its code in the Runtime's report when the code is
/// one the capsule emits, and nothing else from the refusal travels with it.
#[test]
fn custody_private_rejection_keeps_only_a_known_code() {
    assert_eq!(
        super::custody_private_rejection_message(Some("operation_expired")),
        "custody private request was rejected: operation_expired"
    );
    assert_eq!(
        super::custody_private_rejection_message(Some("invalid_request")),
        "custody private request was rejected: invalid_request"
    );
    for code in [
        None,
        Some(""),
        Some("/home/someone/key"),
        Some("0xdeadbeef"),
    ] {
        assert_eq!(
            super::custody_private_rejection_message(code),
            "custody private request was rejected"
        );
    }
}

/// A reply that never arrived is not a node that never acted: the capsule can
/// complete its write and then fail to answer.
#[test]
fn a_missing_or_malformed_custody_reply_is_effect_uncertain() {
    assert_eq!(
        super::classify_custody_failure(
            "provision_node_share",
            &super::ProviderInvocationFailure::NotCompleted {
                detail: "transport closed".to_string(),
            },
        ),
        RuntimeProviderCallError::NoExactResult
    );
    assert_eq!(
        super::classify_custody_failure(
            "provision_node_share",
            &super::ProviderInvocationFailure::MalformedResponse {
                detail: "custody provider provision_node_share response is missing status"
                    .to_string(),
            },
        ),
        RuntimeProviderCallError::NoExactResult
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
        super::runtime_custody_listing_summary(temp.path(), "person:local:buyer", &media).unwrap();
    assert_eq!(media_summary["content_kind"], "media");
    assert_eq!(media_summary["access_state"], "available");

    let (_, package) = object_listing_package_for_test(0x7b);
    let object = super::RuntimeCustodyListingRecord {
        origin: super::RuntimeCustodyListingOrigin::LocalCreator {
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
        super::runtime_custody_listing_summary(temp.path(), "person:local:creator", &object)
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
        super::runtime_custody_content_kind(&media),
        super::RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA
    );
    assert_eq!(
        super::expected_runtime_custody_viewer_capsule(&media),
        super::ELACITY_PLAYER_CAPSULE_ID
    );

    let (object_identity, _) = object_listing_package_for_test(0x7c);
    let object = RuntimeContentIdentityV1::Object(object_identity);
    assert_eq!(
        super::runtime_custody_content_kind(&object),
        super::RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_OBJECT
    );
    assert_eq!(
        super::expected_runtime_custody_viewer_capsule(&object),
        super::ELACITY_READER_CAPSULE_ID
    );
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
        let round_trip: super::RuntimePortableListingPackage =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&round_trip).unwrap(), bytes);
    }
}

// --- Read after a buy: the shared read dataset and adopted listings -------

const SHARED_PUBLISHER: &str = "0xAB5028BDBB0826AD6F1885478E421DB677B0001A";

/// The four identities a package carries, as the shared document states them.
struct SharedIdentities {
    kid: String,
    content_type: String,
    rights_policy: String,
    key_envelope: String,
    content_key_commitment: String,
    content_identity: String,
}

impl SharedIdentities {
    fn of_package(package: &super::RuntimePortableListingPackage, content_type: &str) -> Self {
        Self {
            kid: package.content_access_id.clone(),
            content_type: content_type.to_string(),
            rights_policy: package.rights_policy_identity_base64.clone(),
            key_envelope: package.key_envelope_identity_base64.clone(),
            content_key_commitment: package.content_key_commitment_base64.clone(),
            content_identity: package
                .media_identity_base64
                .clone()
                .or_else(|| package.content_identity_base64.clone())
                .unwrap(),
        }
    }
}

/// The shared `metadata.json` exactly as this Runtime's producer writes it --
/// never hand-written -- for the given identities.
fn shared_metadata_from_producer(identities: &SharedIdentities) -> Value {
    let inputs = crate::protected_content_elacity_metadata::ElacityMetadataInputs {
        encrypted_content_cid: ContentAvailabilityTestProvider::CID,
        content_type: &identities.content_type,
        plaintext_bytes: 5,
        kid_0x: &identities.kid,
        publisher_address: SHARED_PUBLISHER,
        chain_id: 8453,
        ledger: "0x0000000000000000000000000000000000000022",
        authority: "",
        copies: 2,
        price: "5",
        image: "",
        protection: crate::protected_content_elacity_metadata::runtime_custody_protection(
            2,
            3,
            crate::protected_content_elacity_metadata::ProtectedContentIdentities {
                rights_policy: &identities.rights_policy,
                key_envelope: &identities.key_envelope,
                content_key_commitment: &identities.content_key_commitment,
                content_identity: &identities.content_identity,
                pool_mint_share: None,
            },
        ),
        fallback_name: "shared-proof.mp4",
        created_at: "2026-09-25T00:00:00Z",
        access_method: elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyOnce,
        reseller_cut: None,
    };
    let files =
        crate::protected_content_elacity_metadata::elacity_metadata_files(None, &inputs).unwrap();
    assert_eq!(files[0].0, "metadata.json");
    serde_json::from_slice(&files[0].1).unwrap()
}

fn media_listing_package_for_shared_test() -> super::RuntimePortableListingPackage {
    runtime_custody_listing_record_for_test(
        Digest32::new([0x74; 32]),
        "person:local:shared",
        "shared",
        NOW,
    )
    .package
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
        super::runtime_portable_identity_fields(&dataset.content_identity).unwrap(),
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
        super::runtime_portable_identity_fields(&dataset.content_identity).unwrap(),
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

/// An adopted record (origin `Asset`) of the fixture's own package.
fn adopted_listing_record_for_test() -> super::RuntimeCustodyListingRecord {
    let mut record = runtime_custody_listing_record_for_test(
        Digest32::new([0x76; 32]),
        "person:local:adopted",
        "adopted",
        NOW,
    );
    record.package.mint_transaction_hash = None;
    record.package.published_at = None;
    record.package.publisher_profile_did = format!(
        "did:pkh:eip155:8453:{}",
        SHARED_PUBLISHER.to_ascii_lowercase()
    );
    record.origin = super::RuntimeCustodyListingOrigin::Asset {
        asset_uri: format!("elastos://{}", record.package.metadata_cid),
    };
    record
}

/// Re-states a published record's `package_sha256` over its current package,
/// so a check that fails is the one under test and not the digest.
fn restate_published_digest(record: &mut super::RuntimeCustodyListingRecord) {
    let digest = hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&record.package).unwrap(),
    ));
    match &mut record.origin {
        super::RuntimeCustodyListingOrigin::LocalCreator { package_sha256, .. }
        | super::RuntimeCustodyListingOrigin::Imported { package_sha256, .. } => {
            *package_sha256 = digest;
        }
        super::RuntimeCustodyListingOrigin::Asset { .. }
        | super::RuntimeCustodyListingOrigin::Granted { .. } => {}
    }
}

fn granted_listing_record_for_test() -> super::RuntimeCustodyListingRecord {
    let mut record = adopted_listing_record_for_test();
    record.origin = super::RuntimeCustodyListingOrigin::Granted {
        asset_uri: format!("elastos://{}", record.package.metadata_cid),
    };
    record.package.seller_address = record.package.operative.to_ascii_lowercase();
    record.package.quantity = "0x1".to_string();
    record.package.price = "0x0".to_string();
    record.package.pay_token = super::RUNTIME_CUSTODY_ZERO_ADDRESS.to_string();
    record.package.payment_processor = None;
    record
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
    let refused = |label: &str, change: &dyn Fn(&mut super::RuntimeCustodyListingRecord)| {
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
        serde_json::to_value(super::RuntimeCustodyAcquisitionV1::Granted).unwrap(),
        json!("granted")
    );
    assert_eq!(
        super::RuntimeCustodyAcquisitionV1::Granted.wire_value(),
        "granted"
    );
    for (acquisition, wire) in [
        (super::RuntimeCustodyAcquisitionV1::Bought, "bought"),
        (super::RuntimeCustodyAcquisitionV1::Minted, "minted"),
        (super::RuntimeCustodyAcquisitionV1::Market, "market"),
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

    let refused = |label: &str, change: &dyn Fn(&mut super::RuntimeCustodyListingRecord)| {
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
        record.origin = super::RuntimeCustodyListingOrigin::Asset {
            asset_uri: "elastos://QmcKGaG3CsCw93bc5JgDehrQTM7h1LMF1BQQiLXCvPvfz2".to_string(),
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
                record.origin = super::RuntimeCustodyListingOrigin::Imported {
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
                Box::new(|record: &mut super::RuntimeCustodyListingRecord| {
                    record.package.mint_transaction_hash = None;
                }) as Box<dyn Fn(&mut super::RuntimeCustodyListingRecord)>,
            ),
            (
                "no publication time",
                Box::new(|record: &mut super::RuntimeCustodyListingRecord| {
                    record.package.published_at = None;
                }),
            ),
            (
                "a did:pkh publisher",
                Box::new(|record: &mut super::RuntimeCustodyListingRecord| {
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

/// R40 (T8-C3): the `did:pkh` publisher relaxation is an explicit choice made
/// only for an adopted listing (origin `Asset`), never inferred from the
/// requirement's DID method; and even there the manifest must name a real
/// `did:key`, not merely something.
#[test]
fn manifest_publisher_binding_is_chosen_by_origin_and_requires_a_did_key() {
    use super::{content_manifest_binds_publisher, RuntimeManifestPublisherBinding as Binding};
    let did_key = derived_device_key_for_seed(0x66).1;
    let pkh = "did:pkh:eip155:8453:0x00000000000000000000000000000000000000a4";
    let requirement = |publisher: &str| {
        RuntimeContentAvailabilityRequirement::new(
            did_key.clone(),
            "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content",
            publisher,
            super::PROTECTED_CONTENT_REPLICATION_POLICY,
            super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
            super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
            super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
        )
        .unwrap()
    };
    let manifest = |publisher: Option<&str>| crate::content::ContentObjectManifest {
        schema: "elastos.content.object.manifest/v1".to_string(),
        kind: "directory".to_string(),
        content_digest: String::new(),
        files: Vec::new(),
        links: Vec::new(),
        object_did: None,
        publisher_did: publisher.map(str::to_string),
    };
    // An adopted listing: the manifest names the Runtime profile that
    // published the bytes, a well-formed did:key.
    assert!(content_manifest_binds_publisher(
        &manifest(Some(&did_key)),
        &requirement(pkh),
        Binding::AdoptedAttribution,
    ));
    for named in [Some("did:web:example.com"), Some("x"), Some(pkh), None] {
        assert!(
            !content_manifest_binds_publisher(
                &manifest(named),
                &requirement(pkh),
                Binding::AdoptedAttribution,
            ),
            "{named:?} is not a publisher's did:key"
        );
    }
    // The relaxation is never inferred from the requirement's method.
    assert!(!content_manifest_binds_publisher(
        &manifest(Some(&did_key)),
        &requirement(pkh),
        Binding::Exact,
    ));
    assert!(content_manifest_binds_publisher(
        &manifest(Some(&did_key)),
        &requirement(&did_key),
        Binding::Exact,
    ));
    // And an adopted binding still needs the adopted (did:pkh) requirement.
    assert!(!content_manifest_binds_publisher(
        &manifest(Some(&did_key)),
        &requirement(&did_key),
        Binding::AdoptedAttribution,
    ));
    // Only origin `Asset` chooses it.
    assert_eq!(
        Binding::for_origin(&super::RuntimeCustodyListingOrigin::Asset {
            asset_uri: "elastos://bafyfixture".to_string(),
        }),
        Binding::AdoptedAttribution
    );
    assert_eq!(
        Binding::for_origin(&super::RuntimeCustodyListingOrigin::Imported {
            listing_uri: "elastos://bafyfixture".to_string(),
            package_sha256: "00".repeat(32),
        }),
        Binding::Exact
    );
}

const FINALITY_WALLET: &str = "0x0000000000000000000000000000000000000007";

fn finality_access_answer(request: &Value, has_access: bool) -> Value {
    ok_provider_response(json!({
        "schema": "elastos.chain.protected-content-purchase-access/v1",
        "request_id": request["request_id"],
        "network": "base-mainnet",
        "chain_id": 8453,
        "wallet": FINALITY_WALLET,
        "content_access_id": request["content_access_id"],
        "has_access": has_access,
        "finalized_block_number": 44,
        "finalized_block_hash": format!("0x{}", "cc".repeat(32)),
        "finalized_block_timestamp": 1_000,
        "observed_at": 1_000,
    }))
}

fn finality_unbound_answer() -> Value {
    json!({
        "status": "error",
        "code": "unknown_protected_content_object",
        "message": "protected-content content access id is not bound on chain",
    })
}

/// The request the finality check sends, so each answer can echo it.
fn finality_request(block: &str) -> Value {
    json!({
        "request_id": format!("open-finality:{block}"),
        "content_access_id": format!("0x{}", hex::encode(content_access_id(0x51).as_bytes())),
    })
}

async fn finality_progress_with(
    answers: Vec<Result<Value, ProviderError>>,
    confirmed_at: u64,
    now: u64,
) -> (Option<super::RuntimeCustodyOpenProgress>, Vec<Value>) {
    let registry = Arc::new(ProviderRegistry::new());
    let chain = SequencedProvider::new(CHAIN_PROVIDER_ID, answers);
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
        .await
        .unwrap();
    let progress = super::runtime_custody_open_finality_progress(
        registry.as_ref(),
        "base-mainnet",
        FINALITY_WALLET,
        content_access_id(0x51),
        "open-finality",
        confirmed_at,
        now,
    )
    .await;
    (progress, chain.requests().await)
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
        json!(now - 120 + super::RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS)
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
    let confirmed_at = now - super::RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS - 300;
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

/// The typed reason a fail-closed refusal carries, so Creator offers Start over.
fn attempt_conflict_reason(error: &anyhow::Error) -> RuntimeCustodyAttemptConflictReason {
    error
        .downcast_ref::<RuntimeCustodyAttemptConflict>()
        .unwrap_or_else(|| panic!("refusal must carry the attempt conflict as data: {error:#}"))
        .reason()
}

/// Start over, as the gateway does it: the source's current attempt is moved
/// aside and the source is on a new attempt.
fn start_over_for_test(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) {
    runtime_mint_journal(data_dir)
        .archive_current_attempt(
            principal_id,
            object_uri,
            source_storage,
            &data_dir.join("protected-content/runtime-mint-set-aside-test"),
            b"{}",
        )
        .unwrap();
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
        assert_eq!(super::runtime_portable_content_codecs(&identity), joined);
        assert_eq!(super::runtime_custody_content_kind(&identity), "media");
        assert_eq!(
            super::expected_runtime_custody_viewer_capsule(&identity),
            super::ELACITY_PLAYER_CAPSULE_ID
        );
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

/// Independent of the production path helpers on purpose: a wrong path there
/// must fail a test here.
fn dash_dir(
    kind: elastos_protected_content_provider_contracts::CencDashRenditionKindV2,
) -> &'static str {
    match kind {
        DASH_VIDEO => "protected-content/v2/video/avc1",
        DASH_AUDIO => "protected-content/v2/audio/und/mp4a",
    }
}

fn dash_init_path(
    kind: elastos_protected_content_provider_contracts::CencDashRenditionKindV2,
) -> String {
    format!("{}/init.mp4", dash_dir(kind))
}

fn dash_segment_file(
    kind: elastos_protected_content_provider_contracts::CencDashRenditionKindV2,
    index: usize,
) -> String {
    format!("{}/seg-{}.m4s", dash_dir(kind), index + 1)
}

const DASH_IDENTITY_FILE: &str = "protected-content/v2/identity.bin";
const DASH_MPD_FILE: &str = "protected-content/v2/stream.mpd";

pub(crate) fn media_dash_components(
    kinds: &[elastos_protected_content_provider_contracts::CencDashRenditionKindV2],
    counts: &[usize],
) -> MediaDashComponents {
    media_dash_fixture::protected_media_dash_components(
        0x41,
        kinds,
        counts,
        &signed_custody_epoch().epoch_identity().unwrap(),
    )
}

/// The v2 package layout (spec section 3) as `(path, bytes)`, sorted by path.
/// The MPD is a stand-in: nothing in the read side reads it, and the real one
/// is T10's writer's.
fn dash_package_files(
    head: &elastos_protected_content_provider_contracts::CencDashMediaIdentityV2,
    inits: &[Vec<u8>],
    segments: &[Vec<Vec<u8>>],
) -> Vec<(String, Vec<u8>)> {
    let mut files = vec![
        (
            DASH_IDENTITY_FILE.to_string(),
            head.canonical_bytes().unwrap(),
        ),
        (DASH_MPD_FILE.to_string(), b"<MPD/>".to_vec()),
    ];
    for (rendition, kind) in head.renditions().iter().map(|r| r.kind()).enumerate() {
        files.push((dash_init_path(kind), inits[rendition].clone()));
        for (index, segment) in segments[rendition].iter().enumerate() {
            files.push((dash_segment_file(kind, index), segment.clone()));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

pub(crate) fn components_package_files(components: &MediaDashComponents) -> Vec<(String, Vec<u8>)> {
    dash_package_files(
        &components.head,
        &components.protected_inits,
        &components.protected_segments,
    )
}

pub(crate) fn dash_manifest_from_files(
    files: &[(String, Vec<u8>)],
) -> crate::content::ContentObjectManifest {
    let entries: Vec<crate::content::ContentObjectFile> = files
        .iter()
        .map(|(path, bytes)| content_object_file_for_test(path, bytes))
        .collect();
    crate::content::ContentObjectManifest {
        schema: "elastos.content.object.manifest/v1".to_string(),
        kind: "protected-content".to_string(),
        content_digest: super::content_object_digest(&entries),
        files: entries,
        links: Vec::new(),
        object_did: None,
        publisher_did: None,
    }
}

fn content_object_file_for_test(path: &str, bytes: &[u8]) -> crate::content::ContentObjectFile {
    crate::content::ContentObjectFile {
        path: path.to_string(),
        sha256: hex::encode(sha2::Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}

/// A head over arbitrary bytes (no crypto), for the tests that only need
/// counts and a manifest: `kinds[r]` has `counts[r]` segments.
#[allow(clippy::type_complexity)]
fn fake_dash_package(
    kinds: &[elastos_protected_content_provider_contracts::CencDashRenditionKindV2],
    counts: &[usize],
) -> (
    elastos_protected_content_provider_contracts::CencDashMediaIdentityV2,
    Vec<Vec<u8>>,
    Vec<Vec<Vec<u8>>>,
) {
    use elastos_protected_content_provider_contracts::{
        CencDashMediaIdentityV2, CencDashRenditionBytesV2,
    };
    let inits: Vec<Vec<u8>> = kinds
        .iter()
        .map(|kind| format!("init-{kind:?}").into_bytes())
        .collect();
    let segments: Vec<Vec<Vec<u8>>> = counts
        .iter()
        .enumerate()
        .map(|(rendition, count)| {
            (0..*count)
                .map(|index| vec![rendition as u8 + 1, index as u8, 0x5a, 0xa5])
                .collect()
        })
        .collect();
    let bytes: Vec<CencDashRenditionBytesV2<'_>> = kinds
        .iter()
        .enumerate()
        .map(|(index, kind)| CencDashRenditionBytesV2 {
            kind: *kind,
            timescale: 90_000,
            init_segment: &inits[index],
            segments: &segments[index],
        })
        .collect();
    let head = CencDashMediaIdentityV2::new_from_bytes(content_access_id(0x41), &bytes).unwrap();
    (head, inits, segments)
}

/// Per-rendition Merkle leaves, rebuilt from segment bytes alone.
fn dash_leaves(
    kind: elastos_protected_content_provider_contracts::CencDashRenditionKindV2,
    segments: &[Vec<u8>],
) -> Vec<Digest32> {
    segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            elastos_protected_content_provider_contracts::cenc_dash_segment_leaf_hash(
                kind,
                index as u32,
                Digest32::new(sha2::Sha256::digest(segment).into()),
                segment.len() as u64,
            )
        })
        .collect()
}

fn dash_all_leaves(components: &MediaDashComponents) -> Vec<Vec<Digest32>> {
    components
        .kinds
        .iter()
        .zip(&components.protected_segments)
        .map(|(kind, segments)| dash_leaves(*kind, segments))
        .collect()
}

fn dash_proof(leaves: &[Digest32], index: usize) -> Vec<Digest32> {
    elastos_protected_content_provider_contracts::cenc_dash_merkle_audit_path(leaves, index)
        .unwrap()
}

#[test]
fn dash_part_map_walks_the_fixed_interleave() {
    use super::runtime_media_dash_part as part;
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
            super::runtime_media_dash_part_count(counts),
            "{counts:?}"
        );
    }
    assert_eq!(
        super::runtime_media_dash_part_count(&[u32::MAX, 1]),
        None,
        "a count past u32 has no part count"
    );
    assert_eq!(super::runtime_media_dash_part(&[], 0), None);
}

#[test]
fn dash_segment_cap_fits_the_provider_frame() {
    use elastos_protected_content_provider_contracts::MAX_VIEWER_MEDIA_PART_BYTES_V1;
    let cap = super::MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2;
    assert_eq!(cap, 2 * 1024 * 1024 - 32 * 1024);
    assert!(cap < MAX_VIEWER_MEDIA_PART_BYTES_V1);
    // The echo carries the segment and a clear part no longer than it, as JSON
    // numbers of up to 4 characters each, plus at most 16 KiB of the rest.
    assert!(8 * cap + 16 * 1024 <= 16 * 1024 * 1024);
}

fn dash_test_record() -> super::RuntimeCustodyViewerRecord {
    let principal_id = "person:local:dash-record";
    let profile_did = derived_device_key_for_seed(0x66).1;
    let mint_id = digest(0x77);
    let binding = super::derive_runtime_custody_session_binding(
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
    let session = RuntimeViewerSession::from_persisted_parts(
        digest(0x91),
        opaque_handle(0x21),
        encrypted_content(0x11),
        RightsActionV1::View,
        crate::auth::now_ts() + 60,
    )
    .unwrap();
    super::RuntimeCustodyViewerRecord::from_active_session(
        principal_id,
        &profile_did,
        mint_id,
        "content-id",
        binding,
        &session,
        crate::auth::now_ts(),
    )
    .unwrap()
}

#[test]
fn require_media_dash_part_enforces_the_interleave() {
    let (head, _, _) = fake_dash_package(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]);
    let mut record = dash_test_record();
    // Part 0 is the video init: no index, rendition 0.
    assert_eq!(
        record.require_media_dash_part(&head, None).unwrap(),
        (0, None)
    );
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

fn manifest_error(
    manifest: &crate::content::ContentObjectManifest,
    head: &elastos_protected_content_provider_contracts::CencDashMediaIdentityV2,
) -> String {
    super::verify_protected_content_dash_manifest(manifest, head)
        .unwrap_err()
        .to_string()
}

fn reseal(manifest: &mut crate::content::ContentObjectManifest) {
    manifest.content_digest = super::content_object_digest(&manifest.files);
}

#[test]
fn dash_manifest_gives_the_leaves_of_an_independent_rebuild() {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let manifest = dash_manifest_from_files(&components_package_files(&components));
    let leaves =
        super::verify_protected_content_dash_manifest(&manifest, &components.head).unwrap();
    assert_eq!(leaves, dash_all_leaves(&components));
    // Every kind set verifies.
    for (kinds, counts) in [
        (vec![DASH_VIDEO], vec![3usize]),
        (vec![DASH_AUDIO], vec![1]),
        (vec![DASH_VIDEO, DASH_AUDIO], vec![3, 2]),
    ] {
        let (head, inits, segments) = fake_dash_package(&kinds, &counts);
        let manifest = dash_manifest_from_files(&dash_package_files(&head, &inits, &segments));
        assert!(super::verify_protected_content_dash_manifest(&manifest, &head).is_ok());
    }
}

#[test]
fn dash_manifest_finds_segments_by_path_not_by_position() {
    // `seg-10` sorts before `seg-2`, so position and index disagree from the
    // tenth segment on; the leaf of index 9 must be `seg-10`'s entry.
    let (head, inits, segments) = fake_dash_package(&[DASH_VIDEO], &[12]);
    let manifest = dash_manifest_from_files(&dash_package_files(&head, &inits, &segments));
    let paths: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    let seg10 = paths
        .iter()
        .position(|p| p.ends_with("/seg-10.m4s"))
        .unwrap();
    let seg2 = paths
        .iter()
        .position(|p| p.ends_with("/seg-2.m4s"))
        .unwrap();
    assert!(seg10 < seg2, "the fixture must exercise the sort inversion");
    let leaves = super::verify_protected_content_dash_manifest(&manifest, &head).unwrap();
    assert_eq!(leaves[0], dash_leaves(DASH_VIDEO, &segments[0]));
    assert_eq!(
        leaves[0][9],
        elastos_protected_content_provider_contracts::cenc_dash_segment_leaf_hash(
            DASH_VIDEO,
            9,
            Digest32::new(sha2::Sha256::digest(&segments[0][9]).into()),
            segments[0][9].len() as u64,
        )
    );
}

#[test]
fn dash_manifest_refuses_every_deviation() {
    const INVALID: &str = "protected content object manifest is invalid";
    let (head, inits, segments) = fake_dash_package(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]);
    let base = dash_manifest_from_files(&dash_package_files(&head, &inits, &segments));
    assert!(super::verify_protected_content_dash_manifest(&base, &head).is_ok());
    let video_seg = |n: usize| dash_segment_file(DASH_VIDEO, n);
    let index_of = |manifest: &crate::content::ContentObjectManifest, path: &str| {
        manifest.files.iter().position(|f| f.path == path).unwrap()
    };
    let mut cases: Vec<(&str, crate::content::ContentObjectManifest)> = Vec::new();

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(1));
    m.files.remove(at);
    reseal(&mut m);
    cases.push(("a missing segment", m));

    let mut m = base.clone();
    m.files.push(content_object_file_for_test(
        "protected-content/v2/zzz-extra.bin",
        b"x",
    ));
    reseal(&mut m);
    cases.push(("an extra file", m));

    for (label, renamed) in [
        ("seg-0", format!("{}/seg-0.m4s", dash_dir(DASH_VIDEO))),
        ("seg-01", format!("{}/seg-01.m4s", dash_dir(DASH_VIDEO))),
        ("seg-(count+1)", video_seg(3)),
    ] {
        let mut m = base.clone();
        let at = index_of(&m, &video_seg(if label == "seg-(count+1)" { 2 } else { 0 }));
        m.files[at].path = renamed;
        m.files.sort_by(|l, r| l.path.cmp(&r.path));
        reseal(&mut m);
        cases.push((label, m));
    }

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(0));
    m.files[at].sha256 = hex::encode(sha2::Sha256::digest(b"other"));
    reseal(&mut m);
    cases.push(("a segment sha changed (root mismatch)", m));

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(0));
    m.files[at].size += 1;
    reseal(&mut m);
    cases.push(("a segment size changed (root mismatch)", m));

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(2));
    m.files[at].size = 0;
    reseal(&mut m);
    cases.push(("a zero-size segment", m));

    let mut m = base.clone();
    let at = index_of(&m, &dash_init_path(DASH_AUDIO));
    m.files[at].sha256 = hex::encode(sha2::Sha256::digest(b"other"));
    reseal(&mut m);
    cases.push(("an init sha changed", m));

    let mut m = base.clone();
    let at = index_of(&m, &dash_init_path(DASH_VIDEO));
    m.files[at].size += 1;
    reseal(&mut m);
    cases.push(("an init size changed", m));

    let mut m = base.clone();
    let at = index_of(&m, DASH_IDENTITY_FILE);
    m.files[at].sha256 = hex::encode(sha2::Sha256::digest(b"other"));
    reseal(&mut m);
    cases.push(("an identity sha changed", m));

    let mut m = base.clone();
    m.content_digest = format!("sha256:{}", hex::encode([0u8; 32]));
    cases.push(("a wrong content_digest", m));

    let mut m = base.clone();
    m.links.push(crate::content::ContentObjectLink {
        rel: "x".to_string(),
        cid: ContentAvailabilityTestProvider::CID.to_string(),
    });
    cases.push(("non-empty links", m));

    let mut m = base.clone();
    m.kind = "other".to_string();
    cases.push(("a wrong kind", m));

    let mut m = base.clone();
    m.files.swap(2, 3);
    reseal(&mut m);
    cases.push(("an unsorted path list", m));

    let mut m = base.clone();
    let duplicate = m.files[2].clone();
    m.files.remove(3);
    m.files.insert(2, duplicate);
    reseal(&mut m);
    cases.push(("a duplicate path", m));

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(1));
    m.files[at].sha256 = m.files[at].sha256.to_uppercase();
    reseal(&mut m);
    cases.push(("uppercase hex", m));

    for (label, manifest) in cases {
        assert_eq!(manifest_error(&manifest, &head), INVALID, "{label}");
    }
}

#[test]
fn dash_manifest_refuses_a_segment_over_the_protected_cap() {
    use elastos_protected_content_provider_contracts::{
        CencDashMediaIdentityV2, CencDashRenditionBytesV2,
    };
    let cap = super::MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2;
    for (len, accepted) in [(cap, true), (cap + 1, false)] {
        // A head whose roots match the files, so only the size can refuse.
        let segments = vec![vec![0x5a; len]];
        let head = CencDashMediaIdentityV2::new_from_bytes(
            content_access_id(0x41),
            &[CencDashRenditionBytesV2 {
                kind: DASH_VIDEO,
                timescale: 90_000,
                init_segment: b"init",
                segments: &segments,
            }],
        )
        .unwrap();
        let files = dash_package_files(&head, &[b"init".to_vec()], &[segments]);
        let result =
            super::verify_protected_content_dash_manifest(&dash_manifest_from_files(&files), &head);
        assert_eq!(result.is_ok(), accepted, "{len}");
    }
}

fn dash_listing_package_for_test(
    components: &MediaDashComponents,
) -> (RuntimeMintDraft, super::RuntimePortableListingPackage) {
    let draft = media_dash_mint_draft(components);
    let record = media_dash_listing_record(&draft, "person:local:creator", "dash", NOW);
    (draft, record.package)
}

pub(crate) fn media_dash_mint_draft(components: &MediaDashComponents) -> RuntimeMintDraft {
    let seed = 0x41;
    let epoch = signed_custody_epoch();
    let head = &components.head;
    let manifest = CustodyEnvelopeManifestV1::new(
        head.encrypted_content().clone(),
        CustodyPoolIdentityV1::new(digest(seed ^ 0x34), 512).unwrap(),
        epoch.epoch_identity().unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(seed ^ 0x35), 512).unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        digest(seed ^ 0x33),
        epoch.statement().nodes().to_vec(),
    )
    .unwrap();
    let envelope = CustodyEnvelopeV1::new(
        manifest,
        [seed ^ 0x50, seed ^ 0x51, seed ^ 0x52]
            .into_iter()
            .map(sealed_share)
            .collect(),
    )
    .unwrap();
    let mint_nodes = epoch
        .statement()
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let node_seed = u8::try_from(index + 1).unwrap();
            RuntimeMintNodeBinding::new(
                node.node_public_key(),
                CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
                Digest32::new([0x3f + node_seed; 32]),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::MediaDash(head.clone()),
        content_access_id(seed),
        envelope.key_envelope_identity().unwrap(),
        policy_body_for(
            head.encrypted_content().clone(),
            content_access_id(seed),
            RightsActionV1::View,
        )
        .policy_identity()
        .unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        mint_nodes,
    )
    .unwrap()
}

/// The listing a creator would have published for a v2 draft: the media
/// listing fixture with the identity fields of the draft.
pub(crate) fn media_dash_listing_record(
    draft: &RuntimeMintDraft,
    publisher_principal_id: &str,
    display_name: &str,
    published_at: u64,
) -> super::RuntimeCustodyListingRecord {
    let mut record = runtime_custody_listing_record_for_test(
        draft.mint_id(),
        publisher_principal_id,
        display_name,
        published_at,
    );
    let (media_identity_base64, content_identity_base64) =
        super::runtime_portable_identity_fields(draft.content_identity()).unwrap();
    let package = &mut record.package;
    package.content_id = super::runtime_protected_content_id(draft.encrypted_content()).unwrap();
    package.content_access_id = format!("0x{}", hex::encode(draft.content_access_id().as_bytes()));
    package.media_identity_base64 = media_identity_base64;
    package.content_identity_base64 = content_identity_base64;
    package.key_envelope_identity_base64 = base64::engine::general_purpose::STANDARD
        .encode(draft.key_envelope().canonical_bytes().unwrap());
    package.rights_policy_identity_base64 =
        base64::engine::general_purpose::STANDARD.encode(draft.policy().canonical_bytes().unwrap());
    package.content_key_commitment_base64 =
        base64::engine::general_purpose::STANDARD.encode(draft.content_key_commitment().as_bytes());
    record.origin = super::RuntimeCustodyListingOrigin::LocalCreator {
        principal_id: publisher_principal_id.to_string(),
        listing_uri: format!("elastos://{}", ContentAvailabilityTestProvider::CID),
        package_sha256: hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&record.package).unwrap(),
        )),
    };
    record
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
        serde_json::from_slice::<super::RuntimePortableListingPackage>(text.as_bytes()).unwrap(),
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
        super::decode_runtime_shared_content_identity(&encoded).unwrap(),
        identity
    );
    let media = media_identity(0x41);
    let bare = media.canonical_bytes().unwrap();
    assert!(
        !(0x01..=0x03).contains(&bare[0]),
        "bare v1 media bytes must not collide with a kind byte"
    );
    assert_eq!(
        super::decode_runtime_shared_content_identity(
            &base64::engine::general_purpose::STANDARD.encode(&bare)
        )
        .unwrap(),
        RuntimeContentIdentityV1::Media(media.clone())
    );
    // A kind-prefixed media identity is refused.
    let prefixed = RuntimeContentIdentityV1::Media(media)
        .canonical_bytes()
        .unwrap();
    assert!(super::decode_runtime_shared_content_identity(
        &base64::engine::general_purpose::STANDARD.encode(prefixed)
    )
    .is_err());
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
        let answer = super::runtime_custody_viewer_media_dash_public_response(
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

impl ContentAvailabilityTestProvider {
    /// Publishes arbitrary `(path, bytes)` files, bypassing the v1-only
    /// directory walk.
    async fn seed_published_files(
        &self,
        files: &[(String, Vec<u8>)],
        object_identity: &str,
        publisher_did: &str,
    ) -> Result<(), ProviderError> {
        let entries = files
            .iter()
            .map(|(path, bytes)| {
                json!({
                    "path": path,
                    "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                })
            })
            .collect::<Vec<_>>();
        self.publish(&json!({
            "op": "publish",
            "object_kind": "protected-content",
            "object_did": object_identity,
            "publisher_did": publisher_did,
            "files": entries,
        }))
        .await?;
        Ok(())
    }

    async fn replace_published_file(&self, path: &str, bytes: Vec<u8>) {
        self.files.lock().await.insert(path.to_string(), bytes);
    }

    /// Changes the published manifest, both the one receipts are built from
    /// and the file a fetch returns.
    async fn tamper_published_manifest(
        &self,
        edit: impl FnOnce(&mut crate::content::ContentObjectManifest),
    ) {
        let mut guard = self.manifest.lock().await;
        let manifest = guard.as_mut().expect("published manifest");
        edit(manifest);
        self.files.lock().await.insert(
            crate::content::CONTENT_OBJECT_MANIFEST_PATH.to_string(),
            serde_json::to_vec(manifest).unwrap(),
        );
    }

    async fn fetched_paths(&self) -> Vec<String> {
        self.requests()
            .await
            .iter()
            .filter(|request| request.get("op").and_then(Value::as_str) == Some("fetch"))
            .filter_map(|request| request.get("path").and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    }
}

/// Journals a v2 draft as provisioned and content-available, the state a
/// published mint is in when a buyer meets it.
fn seed_media_dash_mint_journal(
    data_dir: &Path,
    components: &MediaDashComponents,
) -> (RuntimeMintDraft, RuntimeContentAvailabilityRequirement) {
    let data_dir = data_dir.to_path_buf();
    let mint_draft = media_dash_mint_draft(components);
    let fixture_now = crate::auth::now_ts();
    let mint_journal = runtime_mint_journal(&data_dir);
    mint_journal.persist_bound(&mint_draft).unwrap();
    for (index, node) in mint_draft.nodes().iter().enumerate() {
        let seed = u8::try_from(index + 1).unwrap();
        mint_journal
            .mark_node_effect_started(mint_draft.mint_id(), node.node_public_key())
            .unwrap();
        mint_journal
            .mark_node_receipt(
                mint_draft.mint_id(),
                RuntimeMintNodeReceipt::new(
                    node.node_public_key(),
                    RuntimeCustodyProvisioningIdV1::new(digest(0x80 + seed)).unwrap(),
                    CustodyNodeProvisioningRecordIdentityV1::new(digest(0xa0 + seed), 128).unwrap(),
                    node.owner_state_root(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    mint_journal
        .mark_custody_provisioned(mint_draft.mint_id())
        .unwrap();

    let expected_provider_did =
        ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted())
            .signer_did();
    let requirement = RuntimeContentAvailabilityRequirement::new(
        expected_provider_did,
        super::runtime_protected_content_id(mint_draft.encrypted_content()).unwrap(),
        derived_device_key_for_seed(0x66).1,
        super::PROTECTED_CONTENT_REPLICATION_POLICY,
        super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .unwrap();
    let evidence = elastos_protected_content_runtime::RuntimeVerifiedContentAvailability::new(
        ContentAvailabilityTestProvider::CID,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        &requirement,
        3,
        fixture_now.saturating_sub(1),
        digest(0x71),
        mint_draft.encrypted_content().clone(),
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media_dash(
            &components.head,
        ),
    )
    .unwrap();
    mint_journal
        .mark_content_available(mint_draft.mint_id(), &requirement, evidence)
        .unwrap();
    (mint_draft, requirement)
}

struct RuntimeCustodyMediaDashHarness {
    base: RuntimeCustodyPrebuyAvailabilityHarness,
    components: MediaDashComponents,
}

/// Twin of `runtime_custody_prebuy_availability_harness` for a v2 mint: a
/// `MediaDash` draft journalled as available, its listing, and the real
/// package published to the content test provider.
async fn runtime_custody_media_dash_availability_harness(
    components: MediaDashComponents,
    provider_config: ContentAvailabilityTestConfig,
) -> RuntimeCustodyMediaDashHarness {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    write_device_key(&data_dir, 0x61);
    write_library_publish_test_composition(&data_dir);

    let (mint_draft, requirement) = seed_media_dash_mint_journal(&data_dir, &components);
    let fixture_now = crate::auth::now_ts();
    let listing = media_dash_listing_record(
        &mint_draft,
        "person:local:creator",
        "protected-video.mp4",
        fixture_now.saturating_sub(2),
    );
    super::persist_runtime_custody_listing(&data_dir, &listing).unwrap();

    let content_provider = ContentAvailabilityTestProvider::new(0x61, provider_config);
    content_provider
        .seed_published_files(
            &components_package_files(&components),
            requirement.expected_object_identity(),
            requirement.expected_publisher_did(),
        )
        .await
        .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("content", content_provider.clone())
        .await
        .unwrap();
    RuntimeCustodyMediaDashHarness {
        base: RuntimeCustodyPrebuyAvailabilityHarness {
            _temp: temp,
            data_dir,
            registry,
            content_provider,
            mint_id: mint_draft.mint_id(),
        },
        components,
    }
}

/// A v2 listing a gateway test can persist and list, over a real protected
/// package of `kinds` with `counts` segments each.
#[cfg(unix)]
pub(crate) fn seeded_media_dash_listing_for_test(
    kinds: &[elastos_protected_content_provider_contracts::CencDashRenditionKindV2],
    counts: &[usize],
) -> super::RuntimeCustodyListingRecord {
    let components = media_dash_components(kinds, counts);
    let draft = media_dash_mint_draft(&components);
    media_dash_listing_record(&draft, "person:local:creator", "dash.mp4", NOW)
}

/// Seeds a v2 mint a buyer already owns, in `data_dir`: the journalled mint,
/// its listing and the buyer's purchase. Returns the mint id as hex.
#[cfg(unix)]
pub(crate) fn seed_media_dash_purchase_for_gateway_test(
    data_dir: &Path,
    principal_id: &str,
) -> String {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let (draft, _) = seed_media_dash_mint_journal(data_dir, &components);
    let listing = media_dash_listing_record(&draft, "person:local:creator", "dash.mp4", NOW);
    super::persist_runtime_custody_listing(data_dir, &listing).unwrap();
    let mint = runtime_mint_journal(data_dir)
        .load(draft.mint_id())
        .unwrap();
    persist_runtime_custody_purchase_for_mint(
        data_dir,
        &mint,
        principal_id,
        &load_profile_did_for_test(data_dir, principal_id),
        crate::auth::now_ts(),
    );
    hex::encode(draft.mint_id().as_bytes())
}

/// A harness plus a buyer with an active v2 viewer session, ready to read.
struct DashViewer {
    harness: RuntimeCustodyMediaDashHarness,
    principal_id: String,
    proof_binding_id: String,
    session: RuntimeViewerSession,
}

#[cfg(unix)]
async fn dash_viewer(components: MediaDashComponents, label: &str) -> DashViewer {
    let harness = runtime_custody_media_dash_availability_harness(
        components,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = format!("person:local:dash-{label}");
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.base.data_dir, &principal_id);
    let profile_did = load_profile_did_for_test(&harness.base.data_dir, &principal_id);
    let mint = runtime_mint_journal(&harness.base.data_dir)
        .load(harness.base.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.base.data_dir,
        &mint,
        &principal_id,
        &profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.base.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x21),
        crate::auth::now_ts() + 60,
    );
    make_runtime_custody_listing_imported_without_creator_mint(
        &harness.base.data_dir,
        mint.draft().mint_id(),
    );
    DashViewer {
        harness,
        principal_id,
        proof_binding_id,
        session,
    }
}

#[cfg(unix)]
impl DashViewer {
    fn data_dir(&self) -> &Path {
        &self.harness.base.data_dir
    }

    fn mint_id(&self) -> Digest32 {
        self.harness.base.mint_id
    }

    async fn read(
        &self,
        segment_index: Option<u32>,
        chunk_index: Option<u32>,
    ) -> anyhow::Result<Value> {
        super::read_runtime_custody_viewer(
            self.data_dir(),
            self.harness.base.registry.clone(),
            &self.principal_id,
            &hex::encode(self.mint_id().as_bytes()),
            &hex::encode(self.session.viewer_session_handle()),
            TEST_VIEWER_EXECUTABLE_ACTOR,
            Some(TEST_VIEWER_LAUNCH_ID),
            Some(&self.proof_binding_id),
            Some("runtime-session:alpha"),
            Some("grant:alpha"),
            segment_index,
            chunk_index,
        )
        .await
    }

    fn record(&self) -> super::RuntimeCustodyViewerRecord {
        super::load_runtime_custody_viewer_record(
            self.data_dir(),
            &self.principal_id,
            self.mint_id(),
        )
        .unwrap()
        .unwrap()
    }

    fn set_next_part(&self, next: u32) {
        let mut record = self.record();
        record.next_media_part_index = next;
        super::persist_runtime_custody_viewer_record(
            self.data_dir(),
            &self.principal_id,
            self.mint_id(),
            &record,
        )
        .unwrap();
    }

    fn stage_leaves(&self) {
        super::stage_runtime_custody_media_dash_leaves(
            self.data_dir(),
            &self.principal_id,
            self.mint_id(),
            &self.harness.components.head,
            &dash_all_leaves(&self.harness.components),
        )
        .unwrap();
    }

    fn leaves_path(&self) -> PathBuf {
        super::runtime_viewer_leaves_path(self.data_dir(), &self.principal_id, self.mint_id())
    }

    /// The reads a full playback performs, in order, as the decrypt provider
    /// must see them: `(selector, clear part it answers with)`.
    fn expected_reads(&self) -> Vec<(ViewerMediaPartSelectorV1, Vec<u8>)> {
        let components = &self.harness.components;
        let leaves = dash_all_leaves(components);
        let mut reads = Vec::new();
        for rendition in 0..components.kinds.len() {
            reads.push((
                ViewerMediaPartSelectorV1::init_v2(rendition as u8).unwrap(),
                vec![0x10 + rendition as u8],
            ));
        }
        let longest = components
            .protected_segments
            .iter()
            .map(Vec::len)
            .max()
            .unwrap();
        for index in 0..longest {
            for (rendition, segments) in components.protected_segments.iter().enumerate() {
                if let Some(segment) = segments.get(index) {
                    reads.push((
                        ViewerMediaPartSelectorV1::segment_v2(
                            rendition as u8,
                            index as u32,
                            segment.clone(),
                            dash_proof(&leaves[rendition], index),
                        )
                        .unwrap(),
                        vec![0xc0 + rendition as u8, index as u8],
                    ));
                }
            }
        }
        reads
    }

    /// Registers a decrypt provider that answers `reads` in order, echoing
    /// each selector as the real provider does.
    async fn register_decrypt(
        &self,
        reads: &[(ViewerMediaPartSelectorV1, Vec<u8>)],
    ) -> Arc<SequencedProvider> {
        let audit = RuntimeReleaseAuditIdV1::new(self.session.audit_request_id()).unwrap();
        let provider = SequencedProvider::new(
            "decrypt",
            reads
                .iter()
                .map(|(selector, clear)| {
                    Ok(ok_provider_response(
                        serde_json::to_value(
                            DecryptProviderResponseV1::new_viewer_media_part(
                                audit,
                                *self.session.viewer_session_handle(),
                                selector.clone(),
                                clear.clone(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ))
                })
                .collect(),
        );
        self.harness
            .base
            .registry
            .register_runtime_provider_target(
                PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
                provider.clone(),
            )
            .await
            .unwrap();
        provider
    }

    fn assert_decrypt_requests(
        &self,
        recorded: &[Value],
        reads: &[(ViewerMediaPartSelectorV1, Vec<u8>)],
    ) {
        assert_eq!(recorded.len(), reads.len());
        for (recorded, (selector, _)) in recorded.iter().zip(reads) {
            let expected = DecryptProviderRequestV1::new_read_viewer_media_part(
                RuntimeReleaseAuditIdV1::new(self.session.audit_request_id()).unwrap(),
                *self.session.viewer_session_handle(),
                selector.clone(),
            )
            .unwrap();
            assert_exact_runtime_decrypt_invocation(
                recorded,
                "read_viewer_media_part",
                &serde_json::to_value(&expected).unwrap(),
            );
        }
    }
}

fn decoded_part(answer: &Value) -> Vec<u8> {
    assert_eq!(
        answer["schema"],
        "elastos.library.runtime-custody-viewer-part/v1"
    );
    base64::engine::general_purpose::STANDARD
        .decode(answer["data"].as_str().unwrap())
        .unwrap()
}

#[cfg(unix)]
#[tokio::test]
async fn dash_open_replays_an_active_session_with_the_v2_answer_and_no_provider_effects() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
        "replay",
    )
    .await;
    let open = super::open_runtime_custody_viewer(
        viewer.data_dir(),
        viewer.harness.base.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
        super::runtime_custody_viewer_media_dash_public_response(
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
    let (inits, leaves) = super::fetch_runtime_custody_open_media_dash(
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
    let error = super::fetch_runtime_custody_open_media_dash(
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
    assert!(super::fetch_runtime_custody_open_media_dash(
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
            let proof = super::runtime_custody_media_dash_proof(
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
    // At part 0: a segment, and a chunk, are refused.
    assert_eq!(
        viewer.read(Some(0), None).await.unwrap_err().to_string(),
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
                super::stage_runtime_custody_media_dash_leaves(
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

#[cfg(unix)]
#[tokio::test]
async fn dash_viewer_record_bound_is_the_part_count() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
        "bound",
    )
    .await;
    let path =
        super::runtime_viewer_path(viewer.data_dir(), &viewer.principal_id, viewer.mint_id());
    let validate = |next: u32| {
        let mut record = viewer.record();
        record.next_media_part_index = next;
        super::validate_runtime_custody_viewer_record_identity(viewer.data_dir(), &path, &record)
    };
    // 2 inits + 4 segments: a record at the total loads, one past it does not.
    assert!(validate(0).is_ok());
    assert!(validate(6).is_ok());
    assert!(validate(7).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn dash_read_refuses_a_published_segment_over_the_cap_before_decrypting() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
        "cap",
    )
    .await;
    viewer.stage_leaves();
    let reads = viewer.expected_reads();
    let decrypt = viewer.register_decrypt(&reads).await;
    for (selector, _) in reads.iter().take(2) {
        viewer.read(selector.segment_index(), None).await.unwrap();
    }
    viewer
        .harness
        .base
        .content_provider
        .replace_published_file(
            &dash_segment_file(DASH_VIDEO, 0),
            vec![0x7f; super::MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 + 1],
        )
        .await;
    let error = viewer.read(Some(0), None).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "Runtime custody viewer media part is invalid"
    );
    assert_eq!(
        decrypt.requests().await.len(),
        2,
        "only the two inits reached decrypt"
    );
    assert_eq!(viewer.record().next_media_part_index, 2);
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
    let close = super::close_runtime_custody_viewer(
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
    let open = super::open_runtime_custody_viewer(
        &harness.base.data_dir,
        harness.base.registry.clone(),
        super::RuntimeCustodyViewerOpenInput {
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
    let listing = super::load_runtime_custody_listing(&harness.base.data_dir, harness.base.mint_id)
        .unwrap()
        .unwrap();
    let (draft, verified) = super::verify_fresh_runtime_custody_availability(
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
    let listing = super::load_runtime_custody_listing(&harness.base.data_dir, harness.base.mint_id)
        .unwrap()
        .unwrap();
    let error = super::verify_fresh_runtime_custody_availability(
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

// ---------------------------------------------------------------------------
// DASH v2 mint (T10)
// ---------------------------------------------------------------------------

/// What a test media provider says it prepared, as the provider's JSON.
#[cfg(unix)]
fn prepared_output_for_test(
    renditions: &[(&str, &str, &str, usize)],
) -> super::RuntimePreparedMediaProviderOutputV2 {
    serde_json::from_value(json!({
        "schema": "elastos.media-provider.prepared-media/v2",
        "renditions": renditions.iter().map(|(name, mime, codecs, count)| json!({
            "rendition": name,
            "mime_type": mime,
            "codecs": codecs,
            "segment_count": count,
        })).collect::<Vec<_>>(),
    }))
    .unwrap()
}

#[cfg(unix)]
const TEST_VIDEO_DECL: (&str, &str, &str) = ("video", "video/mp4", "avc1.640028");
#[cfg(unix)]
const TEST_AUDIO_DECL: (&str, &str, &str) = ("audio", "audio/mp4", "mp4a.40.2");

/// A fresh owner-only operation root holding a prepared v2 tree.
#[cfg(unix)]
fn prepared_root_for_test(
    renditions: &[(CencDashRenditionKindV2, usize)],
) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let operation_root = temp.path().join("operation");
    owner_only_dir(&operation_root);
    write_prepared_media_v2(&operation_root, renditions);
    (temp, operation_root)
}

/// The preparation receipt recomputed from the spec's framing alone: a
/// rendition count, then per rendition its kind code, pinned pair, init length
/// and hash, segment count, and per segment its index, length and hash.
#[cfg(unix)]
fn independent_preparation_receipt(renditions: &[(CencDashRenditionKindV2, usize)]) -> Digest32 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"elastos.protected-content.runtime-media-preparation-receipt/v1");
    hasher.update([renditions.len() as u8]);
    for (kind, count) in renditions {
        let (code, mime, codecs) = match *kind {
            DASH_VIDEO => (1u8, "video/mp4", "avc1.640028"),
            DASH_AUDIO => (2u8, "audio/mp4", "mp4a.40.2"),
        };
        let init = media_dash_fixture::init(*kind, 1);
        hasher.update([code]);
        hasher.update(mime.as_bytes());
        hasher.update([0]);
        hasher.update(codecs.as_bytes());
        hasher.update([0]);
        hasher.update((init.len() as u64).to_be_bytes());
        hasher.update(sha2::Sha256::digest(&init));
        hasher.update((*count as u64).to_be_bytes());
        for (index, segment) in media_dash_fixture::clear_segments(*kind, *count)
            .iter()
            .enumerate()
        {
            hasher.update((index as u64).to_be_bytes());
            hasher.update((segment.len() as u64).to_be_bytes());
            hasher.update(sha2::Sha256::digest(segment));
        }
    }
    Digest32::new(hasher.finalize().into())
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
        let media = super::load_validated_runtime_prepared_media_v2(
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
        let resumed =
            super::load_settled_runtime_prepared_media_v2(&root, media.preparation_receipt())
                .unwrap();
        assert_eq!(resumed.preparation_receipt(), media.preparation_receipt());
        assert!(super::load_settled_runtime_prepared_media_v2(&root, digest(0x01)).is_err());
    }
}

/// A clear video segment of exactly `len` bytes whose timeline starts at 0.
#[cfg(unix)]
fn video_segment_of_len(len: usize) -> Vec<u8> {
    let probe = media_dash_fixture::clear_segment(
        1,
        0,
        &[
            media_dash_fixture::video_sample(1_000),
            media_dash_fixture::video_sample(200),
        ],
    );
    let slice = 1_000 + len - probe.len();
    let segment = media_dash_fixture::clear_segment(
        1,
        0,
        &[
            media_dash_fixture::video_sample(slice),
            media_dash_fixture::video_sample(200),
        ],
    );
    assert_eq!(segment.len(), len);
    segment
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
        super::load_validated_runtime_prepared_media_v2(root, &prepared_output_for_test(declared))
    };
    let invalid = |result: anyhow::Result<super::RuntimePreparedMediaV2>, label: &str| {
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
        super::load_validated_runtime_prepared_media_v2(&root, &v1),
        "a v1 schema",
    );
    assert!(
        serde_json::from_value::<super::RuntimePreparedMediaProviderOutputV2>(json!({
            "schema": "elastos.media-provider.prepared-media/v2",
            "renditions": [],
            "mime_type": "video/mp4",
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<super::RuntimePreparedMediaProviderOutputV2>(json!({
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
fn audio_decl(count: usize) -> (&'static str, &'static str, &'static str, usize) {
    (
        TEST_AUDIO_DECL.0,
        TEST_AUDIO_DECL.1,
        TEST_AUDIO_DECL.2,
        count,
    )
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
async fn prepared_record_of_a_completed_mint_is_consumed_not_prepared_again() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    write_device_key(&data_dir, 0x21);
    let source =
        media_preparation_source_input(temp.path(), "person:local:media-completed-prepared");
    let mut input = library_publish_test_input(&data_dir, &source.principal_id);
    input.object_uri = source.object_uri.clone();
    input.source_storage = source.source_storage.clone();
    let mint_id = seed_settled_runtime_custody_mint_record(&data_dir, &input, true);
    let journal = runtime_mint_journal(&data_dir);
    journal
        .mark_intent_completed(library_publish_request_id(&input), mint_id)
        .unwrap();
    // The v1 preparation of that mint was never consumed before the upgrade.
    let preparation = RuntimeMediaPreparationRecord::new(
        &source.principal_id,
        &source.object_uri,
        &source.source_storage,
        runtime_media_source_digest(b"bounded source media"),
        MEDIA_PROVIDER_ID,
        source.wallet_account_id.clone(),
        source.wallet_account_address.clone(),
        source.creator_mint_source_digest,
    )
    .unwrap();
    journal.persist_media_preparation(&preparation).unwrap();
    journal
        .mark_media_preparation_effect_started(preparation.request_id())
        .unwrap();
    journal
        .mark_media_preparation_prepared(preparation.request_id(), digest(0xd1))
        .unwrap();
    owner_only_dir(&staging_root.join(hex::encode(preparation.operation_id().as_bytes())));
    let registry = Arc::new(ProviderRegistry::new());

    let RuntimeLibraryMediaPreparation::Consumed { record, .. } =
        prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &source)
            .await
            .expect("a completed mint finishes normally")
    else {
        panic!("expected the preparation to be consumed");
    };
    assert_eq!(record.consumed_mint_id(), Some(mint_id));
}

/// A mint run end to end over mock protect, custody, chain and content
/// providers, with a real prepared v2 tree under the data directory.
#[cfg(unix)]
struct LibraryMintHarness {
    _temp: tempfile::TempDir,
    data_dir: PathBuf,
    registry: Arc<ProviderRegistry>,
    epoch: SignedCustodyEpochV1,
    composition_now: u64,
    input: RuntimeCustodyLibraryPublishInput,
    content: Arc<ContentAvailabilityTestProvider>,
}

#[cfg(unix)]
const TEST_PROTECT_HANDLE: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1] =
    [0x4c; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];

#[cfg(unix)]
async fn library_mint_harness(
    principal: &str,
    renditions: &[(CencDashRenditionKindV2, usize)],
) -> LibraryMintHarness {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let (epoch, composition_now) = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
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
    install_profile_authority_keeping_device_key(&data_dir, principal);
    let (device_key, _) = derived_device_key_for_seed(0x21);
    let content = ContentAvailabilityTestProvider::with_signing_key(
        device_key,
        ContentAvailabilityTestConfig {
            checked_at: crate::auth::now_ts(),
            ..ContentAvailabilityTestConfig::accepted()
        },
    );
    registry
        .register_sub_provider("content", content.clone())
        .await
        .unwrap();
    let input = library_publish_test_input_with_renditions(&data_dir, principal, renditions);
    LibraryMintHarness {
        _temp: temp,
        data_dir,
        registry,
        epoch,
        composition_now,
        input,
        content,
    }
}

#[cfg(unix)]
impl LibraryMintHarness {
    /// The persisted intent and the protected package an honest protect
    /// provider would answer it with.
    fn honest_protect(
        &self,
    ) -> (
        RuntimeMintIntent,
        media_dash_fixture::MediaDashComponents,
        CustodyEnvelopeV1,
    ) {
        let intent = persisted_test_mint_intent(&self.data_dir, &self.registry, &self.input);
        let (components, envelope) = protect_input_for_test(
            &self.input,
            &intent,
            &self.epoch,
            self.composition_now,
            &|_, init| init,
        );
        (intent, components, envelope)
    }

    async fn register_protect(
        &self,
        script: Vec<Result<Value, ProviderError>>,
    ) -> Arc<MediaDashProtectTestProvider> {
        let protect =
            MediaDashProtectTestProvider::new(script, Some(self.input.media.part_reads()));
        self.registry
            .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
            .await
            .unwrap();
        protect
    }

    async fn publish(&self) -> anyhow::Result<super::RuntimeCustodyLibraryPublishFacts> {
        publish_runtime_custody_library_object(
            &self.data_dir,
            self.registry.clone(),
            self.input.clone(),
        )
        .await
    }

    /// No staging directory of a mint is left behind.
    fn assert_no_staging(&self) {
        let leftovers: Vec<_> = fs::read_dir(protected_content_root(&self.data_dir))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("publish-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}

#[cfg(unix)]
fn closed_protect_response() -> Result<Value, ProviderError> {
    Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_closed(TEST_PROTECT_HANDLE).unwrap(),
    ))
}

#[cfg(unix)]
fn cancelled_protect_response() -> Result<Value, ProviderError> {
    Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_cancelled(TEST_PROTECT_HANDLE).unwrap(),
    ))
}

#[cfg(unix)]
fn uuid_text(bytes: &[u8; 16]) -> String {
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The MPD of `components` as an independent build: timelines from the clear
/// segments, sizes from the protected ones.
#[cfg(unix)]
fn expected_dash_mpd(
    input: &RuntimeCustodyLibraryPublishInput,
    components: &media_dash_fixture::MediaDashComponents,
) -> String {
    let (kinds, counts) = test_input_layout(input);
    let clear = media_dash_fixture::clear_media_dash(&kinds, &counts);
    let segments: Vec<Vec<elastos_protected_content_provider_contracts::CencDashMpdSegmentV2>> =
        clear
            .iter()
            .zip(&components.protected_segments)
            .map(|((_, init, clear_segments), protected)| {
                let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
                    init,
                    elastos_protected_content_provider_contracts::CencLayoutProfile::V2,
                )
                .unwrap();
                clear_segments
                    .iter()
                    .zip(protected)
                    .map(|(segment, protected)| {
                        elastos_protected_content_provider_contracts::CencDashMpdSegmentV2 {
                            timeline: session
                                .validate_segment(segment)
                                .unwrap()
                                .timeline()
                                .unwrap(),
                            bytes: protected.len() as u64,
                        }
                    })
                    .collect()
            })
            .collect();
    elastos_protected_content_provider_contracts::build_cenc_dash_mpd_v2(
        &components
            .protected_inits
            .iter()
            .zip(&segments)
            .map(|(protected_init, segments)| {
                elastos_protected_content_provider_contracts::CencDashMpdRenditionV2 {
                    protected_init,
                    segments,
                }
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_streams_the_parts_and_publishes_the_v2_package() {
    let harness = library_mint_harness(
        "person:local:dash-mint-happy",
        &[(DASH_VIDEO, 3), (DASH_AUDIO, 3)],
    )
    .await;
    let (intent, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.push(closed_protect_response());
    let protect = harness.register_protect(script).await;

    let facts = harness.publish().await.expect("a v2 mint must publish");

    // The order of requests: the open, every segment of the video then of the
    // audio, the finalize, the close.
    let requests = protect.requests().await;
    let mut order = vec!["open_protection_session".to_string()];
    for rendition in 0..2 {
        for index in 0..3 {
            order.push(format!("protect_media_segment {rendition} {index}"));
        }
    }
    order.push("finalize_protection_session".to_string());
    order.push("close_protection_session".to_string());
    let seen: Vec<String> = requests
        .iter()
        .map(|request| match request["op"].as_str().unwrap() {
            "protect_media_segment" => format!(
                "protect_media_segment {} {}",
                request["rendition_index"], request["segment_index"]
            ),
            op => op.to_string(),
        })
        .collect();
    assert_eq!(seen, order);
    // The open: the pinned pair of each rendition, and no foreign boxes.
    let open = &requests[0];
    let representations = open["representations"].as_array().unwrap();
    assert_eq!(representations.len(), 2);
    for (representation, (rendition, mime, codecs)) in representations
        .iter()
        .zip([TEST_VIDEO_DECL, TEST_AUDIO_DECL])
    {
        assert_eq!(representation["rendition"], rendition);
        assert_eq!(representation["mime_type"], mime);
        assert_eq!(representation["codecs"], codecs);
        assert_eq!(representation["segment_count"], 3);
    }
    assert!(open.get("extra_pssh_boxes").is_none_or(Value::is_null));
    assert!(!open["content_access_id"].is_null());

    // The draft is a v2 head, provisioned and available.
    let persisted = runtime_mint_journal(&harness.data_dir)
        .load(facts.mint_id)
        .unwrap();
    assert_eq!(
        persisted.draft().media_dash_identity(),
        Some(&components.head)
    );
    assert!(persisted.draft().media_identity().is_none());
    assert_eq!(
        persisted.draft().content_access_id(),
        intent.content_access_id()
    );
    let evidence = persisted.content_availability().unwrap();
    assert_eq!(
        evidence.content_identity_root(),
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media_dash(
            &components.head
        )
    );
    assert_eq!(
        runtime_mint_journal(&harness.data_dir)
            .load_intent(intent.request_id())
            .unwrap()
            .completed_mint_id(),
        Some(facts.mint_id)
    );

    // What was published is the package of spec section 3, byte for byte.
    let published = harness.content.files.lock().await.clone();
    let mut published_paths: Vec<&str> = published
        .keys()
        .map(String::as_str)
        .filter(|path| *path != crate::content::CONTENT_OBJECT_MANIFEST_PATH)
        .collect();
    published_paths.sort_unstable();
    let package = components_package_files(&components);
    let expected_paths: Vec<&str> = package.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(published_paths, expected_paths);
    for (path, bytes) in &package {
        if path != DASH_MPD_FILE {
            assert_eq!(&published[path], bytes, "{path}");
        }
    }
    let mpd = String::from_utf8(published[DASH_MPD_FILE].clone()).unwrap();
    assert_eq!(mpd, expected_dash_mpd(&harness.input, &components));

    // S8: the protection system the inits and the MPD name is the writer
    // binding's, compared with the contracts' own constant.
    let writer = PROTECTION.writer();
    for init in &components.protected_inits {
        let published_init = published
            .values()
            .find(|bytes| *bytes == init)
            .expect("every protected init is published");
        assert!(published_init
            .windows(16)
            .any(|window| window == writer.id.as_bytes()));
    }
    assert!(mpd.contains(&format!(
        "schemeIdUri=\"urn:uuid:{}\" value=\"{}\"",
        uuid_text(writer.id.as_bytes()),
        writer.scheme
    )));
    harness.assert_no_staging();
}

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
async fn media_dash_mint_refuses_too_many_slices_with_a_message_the_creator_can_act_on() {
    let harness = library_mint_harness(
        "person:local:dash-mint-slices",
        &[(DASH_VIDEO, 2), (DASH_AUDIO, 2)],
    )
    .await;
    let (intent, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.truncate(1);
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_failure_with_reason(
            ProviderFailureCodeV1::InvalidRequest,
            elastos_protected_content_provider_contracts::ProtectFailureReasonV2::CencTooManySubsamples,
        )
        .unwrap(),
    )));
    script.push(cancelled_protect_response());
    let protect = harness.register_protect(script).await;

    let error = harness
        .publish()
        .await
        .expect_err("too many slices must be refused");

    assert_eq!(
        error.to_string(),
        super::RUNTIME_CUSTODY_MEDIA_TOO_MANY_SLICES_MESSAGE
    );
    assert_eq!(
        super::RUNTIME_CUSTODY_MEDIA_TOO_MANY_SLICES_MESSAGE,
        "This video has too many slices per frame; re-encode it with fewer slices."
    );
    let requests = protect.requests().await;
    assert_eq!(requests.last().unwrap()["op"], "cancel_protection_session");
    let settled = runtime_mint_journal(&harness.data_dir)
        .load_intent(intent.request_id())
        .unwrap();
    assert_eq!(
        settled.protect_terminal_settlement_label(),
        Some("cancelled")
    );
    harness.assert_no_staging();
}

/// Everything a refused mint must NOT have left: no draft, no staging, and the
/// protect session settled.
#[cfg(unix)]
fn assert_refused_before_any_draft(
    harness: &LibraryMintHarness,
    intent: &RuntimeMintIntent,
    requests: &[Value],
) {
    let scan = runtime_mint_journal(&harness.data_dir)
        .find_mint_record_for_intent(intent.request_id())
        .unwrap();
    assert!(scan.open().is_none() && scan.abandoned().is_empty());
    assert_eq!(
        requests.last().unwrap()["op"],
        "cancel_protection_session",
        "the refused session must still be settled: {requests:?}"
    );
    harness.assert_no_staging();
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

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_refuses_a_prepared_segment_rewritten_after_preparation() {
    let harness = library_mint_harness(
        "person:local:dash-mint-rewritten",
        &[(DASH_VIDEO, 2), (DASH_AUDIO, 2)],
    )
    .await;
    let (intent, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.pop();
    script.push(cancelled_protect_response());
    let protect = harness.register_protect(script).await;
    // The segment is rewritten with another valid clear segment after the
    // preparation receipt was taken (the mock provider protects anything).
    let part = harness
        .input
        .media
        .operation_root
        .join("prepared/video/segments/00000001.m4s");
    let mut bytes = fs::read(&part).unwrap();
    *bytes.last_mut().unwrap() ^= 0x01;
    write_private_file(&part, &bytes);

    let error = harness
        .publish()
        .await
        .expect_err("a rewritten part must be refused");

    assert!(
        error
            .to_string()
            .contains("Runtime custody media preparation output changed"),
        "{error}"
    );
    let requests = protect.requests().await;
    assert_eq!(requests.last().unwrap()["op"], "cancel_protection_session");
    let scan = runtime_mint_journal(&harness.data_dir)
        .find_mint_record_for_intent(intent.request_id())
        .unwrap();
    assert!(scan.open().is_none());
    harness.assert_no_staging();
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_has_no_segment_cap() {
    // Over the old 512 segments: the loader and the protect loop have no count
    // limit, through the mock media provider and a scripted protect.
    static LONG_VIDEO: [TestPreparedRendition; 1] = [TestPreparedRendition {
        kind: DASH_VIDEO,
        mime_type: "video/mp4",
        codecs: "avc1.640028",
        segments: 600,
    }];
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let source = media_preparation_source_input(temp.path(), "person:local:dash-mint-long-source");
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root,
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::Prepared(&LONG_VIDEO),
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider)
        .await
        .unwrap();
    let RuntimeLibraryMediaPreparation::Prepared(prepared) =
        prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &source)
            .await
            .expect("600 segments must prepare")
    else {
        panic!("expected a prepared media");
    };
    assert_eq!(prepared.input.media.renditions[0].segment_count, 600);

    // And the mint streams all 600 through the protect provider.
    let mut harness =
        library_mint_harness("person:local:dash-mint-long-protect", &[(DASH_VIDEO, 600)]).await;
    harness.input.media = prepared.input.media.clone();
    let (_, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.push(closed_protect_response());
    let protect = harness.register_protect(script).await;
    harness.publish().await.expect("a long mint must publish");
    assert_eq!(protect.requests().await.len(), 600 + 3);
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_refuses_a_protected_segment_over_the_cap_and_the_cap_fits_the_frame() {
    let cap = super::MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2;
    // Part one: a provider that answers a segment of cap + 1 bytes is refused
    // before anything of it is staged, and the session is settled.
    let harness = library_mint_harness(
        "person:local:dash-mint-over-cap",
        &[(DASH_VIDEO, 2), (DASH_AUDIO, 2)],
    )
    .await;
    let (intent, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.truncate(1);
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_segment_protected(
            TEST_PROTECT_HANDLE,
            0,
            &vec![0xaa; cap + 1],
        )
        .unwrap(),
    )));
    script.push(cancelled_protect_response());
    let protect = harness.register_protect(script).await;
    let error = harness
        .publish()
        .await
        .expect_err("an over-cap segment must be refused");
    assert!(
        error
            .to_string()
            .contains("a prepared media part exceeds the 2 MiB part limit"),
        "{error}"
    );
    assert_refused_before_any_draft(&harness, &intent, &protect.requests().await);

    // Part two: the worst-case decrypt answer at the cap (4 characters per byte
    // in both the encrypted segment and the clear part, a full proof) fits the
    // provider frame, and the same answer at 2 MiB does not -- so the cap is
    // what keeps a read inside the frame.
    let audit = RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap();
    let handle = [0x41; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    let frame = |len: usize| {
        DecryptProviderResponseV1::new_viewer_media_part(
            audit,
            handle,
            ViewerMediaPartSelectorV1::segment_v2(
                1,
                7,
                vec![0xff; len],
                vec![Digest32::new([0xff; 32]); 32],
            )
            .unwrap(),
            vec![0xff; len],
        )
        .unwrap()
        .to_json_vec()
    };
    let at_cap = frame(cap).expect("the worst case at the cap must encode");
    assert!(
        at_cap.len() <= elastos_protected_content_provider_contracts::MAX_PROVIDER_FRAME_BYTES_V1
    );
    let over = frame(2 * 1024 * 1024);
    assert!(
        over.map_or(true, |bytes| {
            bytes.len() > elastos_protected_content_provider_contracts::MAX_PROVIDER_FRAME_BYTES_V1
        }),
        "the cap must be load-bearing"
    );
}

/// The staged package of `components`, written the way the mint stages it.
#[cfg(unix)]
fn stage_dash_package(
    components: &media_dash_fixture::MediaDashComponents,
    mpd: &[u8],
) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    for (path, bytes) in components_package_files(components) {
        let bytes = if path == DASH_MPD_FILE {
            mpd.to_vec()
        } else {
            bytes
        };
        let target = directory.path().join(&path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    directory
}

#[test]
fn dash_directory_check_accepts_the_package_and_refuses_every_deviation() {
    let components = media_dash_components(&[DASH_VIDEO], &[12]);
    let head = &components.head;
    let check =
        |directory: &Path| super::verify_protected_content_dash_directory(directory, head, None);
    let ok = stage_dash_package(&components, b"<MPD/>");
    check(ok.path()).expect("the staged package is accepted");

    // Segments 2 and 10 swapped: by path the roots differ.
    let swapped = stage_dash_package(&components, b"<MPD/>");
    let two = swapped.path().join(dash_segment_file(DASH_VIDEO, 1));
    let ten = swapped.path().join(dash_segment_file(DASH_VIDEO, 9));
    let (two_bytes, ten_bytes) = (fs::read(&two).unwrap(), fs::read(&ten).unwrap());
    fs::write(&two, ten_bytes).unwrap();
    fs::write(&ten, two_bytes).unwrap();
    assert!(check(swapped.path()).is_err(), "swapped segments");

    let extra = stage_dash_package(&components, b"<MPD/>");
    fs::write(extra.path().join("protected-content/v2/extra.bin"), b"x").unwrap();
    assert!(check(extra.path()).is_err(), "an extra file");

    let no_mpd = stage_dash_package(&components, b"<MPD/>");
    fs::remove_file(no_mpd.path().join(DASH_MPD_FILE)).unwrap();
    assert!(check(no_mpd.path()).is_err(), "no stream.mpd");

    let empty_mpd = stage_dash_package(&components, b"");
    assert!(check(empty_mpd.path()).is_err(), "an empty stream.mpd");

    let changed = stage_dash_package(&components, b"<MPD/>");
    let identity = changed.path().join(DASH_IDENTITY_FILE);
    let mut bytes = fs::read(&identity).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&identity, bytes).unwrap();
    assert!(check(changed.path()).is_err(), "a changed identity.bin");

    // A head whose roots match the files, but whose files are not media.
    let (fake_head, fake_inits, fake_segments) = fake_dash_package(&[DASH_VIDEO], &[3]);
    let broken = tempfile::tempdir().unwrap();
    for (path, bytes) in dash_package_files(&fake_head, &fake_inits, &fake_segments) {
        let target = broken.path().join(&path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    assert!(
        super::verify_protected_content_dash_directory(broken.path(), &fake_head, None).is_err(),
        "a valid-hash package with a broken layout"
    );

    // The timelines the protection must have preserved.
    let (kinds, counts) = (vec![DASH_VIDEO], vec![12usize]);
    let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
        &media_dash_fixture::init(DASH_VIDEO, 1),
        elastos_protected_content_provider_contracts::CencLayoutProfile::V2,
    )
    .unwrap();
    let timelines: Vec<Vec<_>> = media_dash_fixture::clear_media_dash(&kinds, &counts)
        .iter()
        .map(|(_, _, segments)| {
            segments
                .iter()
                .map(|segment| {
                    session
                        .validate_segment(segment)
                        .unwrap()
                        .timeline()
                        .unwrap()
                })
                .collect()
        })
        .collect();
    super::verify_protected_content_dash_directory(ok.path(), head, Some(&timelines))
        .expect("the recorded timelines match");
    let mut wrong = timelines.clone();
    wrong[0][3].decode_time += 1;
    assert!(
        super::verify_protected_content_dash_directory(ok.path(), head, Some(&wrong)).is_err(),
        "a timeline that was not preserved"
    );
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
    let evidence = super::publish_and_verify_protected_content_dash_availability(
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
        super::publish_and_verify_protected_content_dash_availability(
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
        super::publish_and_verify_protected_content_dash_availability(
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

/// An in-process protect provider that answers a precomputed script and
/// remembers only the operation names, so an 80 MiB mint does not retain its
/// own request bodies.
#[cfg(unix)]
struct ObjectProtectTestProvider {
    responses: Mutex<VecDeque<Result<Value, ProviderError>>>,
    ops: Mutex<Vec<String>>,
}

#[cfg(unix)]
#[async_trait::async_trait]
impl Provider for ObjectProtectTestProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "object protect test provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![PROTECT_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        PROTECT_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.ops
            .lock()
            .await
            .push(request["op"].as_str().unwrap_or_default().to_string());
        self.responses.lock().await.pop_front().unwrap_or_else(|| {
            Err(ProviderError::Provider(
                "object protect test provider script is exhausted".to_string(),
            ))
        })
    }
}

#[cfg(unix)]
struct ObjectMintFixture {
    harness: LibraryMintHarness,
    input: RuntimeCustodyLibraryPublishObjectInput,
    protect: Arc<ObjectProtectTestProvider>,
    sealed: UnprovisionedSealedPayloadV1,
    plaintext: Vec<u8>,
    max_framed_chunk: usize,
}

/// A mint of `plaintext_bytes` through an honest, scripted object protect
/// provider. A real sealer produced every response, so the Runtime's identity
/// and envelope checks run for real. `fail_at_chunk` makes that chunk fail.
#[cfg(unix)]
async fn object_mint_fixture(
    principal: &str,
    plaintext_bytes: usize,
    fail_at_chunk: Option<usize>,
) -> ObjectMintFixture {
    let harness = library_mint_harness(principal, &[(DASH_VIDEO, 1)]).await;
    let plaintext: Vec<u8> = (0..plaintext_bytes)
        .map(|index| (index % 251) as u8)
        .collect();
    let (mut sealer, framed_header) =
        PayloadSealerV1::open("application/pdf", plaintext_bytes as u64).unwrap();
    let mut script = vec![Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_object_opened(&framed_header).unwrap(),
    ))];
    let mut max_framed_chunk = 0;
    for (index, chunk) in plaintext.chunks(1_048_576).enumerate() {
        let framed = sealer.seal_chunk(index as u32, chunk).unwrap();
        max_framed_chunk = max_framed_chunk.max(framed.len());
        if fail_at_chunk == Some(index) {
            script.push(Err(ProviderError::Provider("scripted failure".to_string())));
            script.push(cancelled_protect_response());
        }
        if fail_at_chunk.is_some_and(|failed| index >= failed) {
            continue;
        }
        script.push(Ok(ok_typed_protect_provider_response(
            ProtectProviderResponseV1::new_object_chunk_protected(&framed).unwrap(),
        )));
    }
    let sealed = sealer.finish_unprovisioned().unwrap();
    if fail_at_chunk.is_none() {
        let committee =
            validated_custody_committee_for_epoch(&harness.epoch, harness.composition_now);
        let envelope = provision_custody_envelope(
            sealed.encrypted_content_identity().clone(),
            sealed.content_key(),
            &committee,
        )
        .unwrap();
        let identity = ChunkedPayloadObjectIdentityV1::new(
            sealed.encrypted_content_identity().clone(),
            "application/pdf",
            plaintext_bytes as u64,
            u32::try_from(framed_header.len()).unwrap(),
        )
        .unwrap();
        script.push(Ok(ok_typed_protect_provider_response(
            ProtectProviderResponseV1::new_object_finalized(
                &identity,
                envelope.manifest().content_key_commitment(),
                &envelope,
            )
            .unwrap(),
        )));
        script.push(closed_protect_response());
    }
    let protect = Arc::new(ObjectProtectTestProvider {
        responses: Mutex::new(script.into()),
        ops: Mutex::new(Vec::new()),
    });
    harness
        .registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();
    let input = RuntimeCustodyLibraryPublishObjectInput {
        object_uri: format!(
            "{}/Documents/large.pdf",
            crate::auth::principal_localhost_root(principal)
        ),
        principal_id: principal.to_string(),
        content_type: "application/pdf".to_string(),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "5".to_string(),
        channel: "0x0000000000000000000000000000000000000022".to_string(),
        pay_token: String::new(),
        clear_plaintext: plaintext.clone(),
        source_storage: "plain_localhost_root".to_string(),
        listing: None,
        pool_did: None,
    };
    ObjectMintFixture {
        harness,
        input,
        protect,
        sealed,
        plaintext,
        max_framed_chunk,
    }
}

#[cfg(unix)]
#[tokio::test]
async fn object_publish_streams_an_object_above_the_old_cap() {
    let fixture = object_mint_fixture("person:local:object-80mib", 80 * 1024 * 1024, None).await;
    let facts = publish_runtime_custody_library_object_content(
        &fixture.harness.data_dir,
        fixture.harness.registry.clone(),
        fixture.input.clone(),
    )
    .await
    .expect("an object above the old 64 MiB cap must publish");

    let ops = fixture.protect.ops.lock().await.clone();
    assert_eq!(
        ops.iter()
            .filter(|op| op.as_str() == "protect_object_chunk")
            .count(),
        80
    );
    assert!(fixture.max_framed_chunk <= MAX_OBJECT_FRAMED_CHUNK_BYTES_V1);
    let persisted = runtime_mint_journal(&fixture.harness.data_dir)
        .load(facts.mint_id)
        .unwrap();
    let Some(RuntimeContentIdentityV1::Object(identity)) =
        Some(persisted.draft().content_identity())
    else {
        panic!("the draft must carry an object identity");
    };
    assert_eq!(identity.chunk_count(), 80);
    assert_eq!(
        identity.encrypted_content(),
        fixture.sealed.encrypted_content_identity()
    );
    fixture.harness.assert_no_staging();
}

#[cfg(unix)]
#[tokio::test]
async fn object_protect_failure_leaves_no_staging() {
    let fixture = object_mint_fixture("person:local:object-fails", 5 * 1024 * 1024, Some(3)).await;
    assert!(publish_runtime_custody_library_object_content(
        &fixture.harness.data_dir,
        fixture.harness.registry.clone(),
        fixture.input.clone(),
    )
    .await
    .is_err());
    fixture.harness.assert_no_staging();
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

#[cfg(unix)]
async fn object_epc1_fetches(harness: &LibraryMintHarness) -> usize {
    harness
        .content
        .requests()
        .await
        .iter()
        .filter(|request| {
            request["op"] == "fetch" && request["path"] == PROTECTED_CONTENT_OBJECT_EPC1_PATH
        })
        .count()
}

// ── #388 A1: the custody roles on an everyday host ──────────────────

/// Every custody op that touches another party's content key is refused on
/// an everyday host, with that op's existing effect-free code, so a remote
/// coordinator fails over; every statement kind of `sign_pool_statement` is
/// refused alike. Status and the rights evaluation are not gated.
#[test]
fn restart_with_existing_roots_on_an_everyday_host_releases_no_key() {
    use super::{custody_host_trust_refusal, CUSTODY_EFFECT_FREE_REFUSAL_CODES};
    use crate::custody_surface::{
        OP_CUSTODY_EVALUATE, OP_CUSTODY_PROVISION_NODE_SHARE, OP_CUSTODY_RELEASE_CONTRIBUTION,
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, OP_CUSTODY_SIGN_POOL_STATEMENT, OP_CUSTODY_STATUS,
    };
    for (op, code) in [
        (OP_CUSTODY_RELEASE_CONTRIBUTION, "invalid_request"),
        (OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, "unknown_envelope"),
        (OP_CUSTODY_PROVISION_NODE_SHARE, "provisioning_refused"),
        (OP_CUSTODY_SIGN_POOL_STATEMENT, "invalid_request"),
    ] {
        let refusal = custody_host_trust_refusal(op, false).unwrap_or_else(|| panic!("{op}"));
        assert_eq!(refusal["status"], "error", "{op}");
        assert_eq!(refusal["code"], code, "{op}");
        assert!(CUSTODY_EFFECT_FREE_REFUSAL_CODES.contains(&code), "{op}");
    }
    for op in [OP_CUSTODY_STATUS, OP_CUSTODY_EVALUATE] {
        assert!(custody_host_trust_refusal(op, false).is_none(), "{op}");
    }
}

#[test]
fn switching_to_wci_operated_and_restarting_restores_every_role() {
    use super::custody_host_trust_refusal;
    use crate::custody_surface::{
        OP_CUSTODY_EVALUATE, OP_CUSTODY_PROVISION_NODE_SHARE, OP_CUSTODY_RELEASE_CONTRIBUTION,
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, OP_CUSTODY_SIGN_POOL_STATEMENT, OP_CUSTODY_STATUS,
    };
    for op in [
        OP_CUSTODY_RELEASE_CONTRIBUTION,
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
        OP_CUSTODY_PROVISION_NODE_SHARE,
        OP_CUSTODY_SIGN_POOL_STATEMENT,
        OP_CUSTODY_STATUS,
        OP_CUSTODY_EVALUATE,
    ] {
        assert!(custody_host_trust_refusal(op, true).is_none(), "{op}");
    }
}

/// The registered wrapper of an everyday host still loads its existing root
/// (Hosting lists it) but never forwards a gated op: the provider sees only
/// its start-up, and the custody root is left byte for byte.
#[cfg(unix)]
#[tokio::test]
async fn existing_roots_shares_replay_and_journals_are_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    fs::write(state_root.join("existing-share.bin"), b"share bytes").unwrap();
    let before = fs::read(state_root.join("existing-share.bin")).unwrap();
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());
    crate::host_trust::seed_for_test(&data_dir, false);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    assert!(
        registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );
    for op in [
        "release_contribution",
        "release_pool_contribution",
        "provision_node_share",
        "sign_pool_statement",
        "provision_pool_node_share",
    ] {
        let refused = invoke_json_provider(
            registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            op,
            json!({"op": op}),
        )
        .await;
        assert!(refused.is_err(), "{op}: {refused:?}");
    }
    let requests = fs::read_to_string(&request_log).unwrap();
    assert_eq!(
        requests.lines().count(),
        2,
        "init and status only: {requests}"
    );
    assert_eq!(
        fs::read(state_root.join("existing-share.bin")).unwrap(),
        before
    );
}

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

    #[tokio::test]
    async fn adopted_listing_on_non_holder_verifies_by_fetch() {
        let (_dir, registry, provider, identity, content_id) = published_media().await;
        let before = provider.requests.lock().await.len();
        let evidence = pcr::verify_non_holder_content(
            registry.as_ref(),
            ContentAvailabilityTestProvider::CID,
            &content_id,
            &identity,
            pcr::NonHolderCheck::FullFetch,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(
            evidence.kind(),
            RuntimeAvailabilityEvidenceV1::VERIFIED_FETCH
        );
        assert_eq!(evidence.receipt_digest(), None);
        assert_eq!(evidence.observed_replicas(), 0);
        assert_eq!(evidence.content_cid(), ContentAvailabilityTestProvider::CID);
        assert_eq!(evidence.object_identity(), content_id);
        // Every file was fetched; nothing was ensured or pinned here, so an
        // offline local store cannot refuse the adoption.
        let ops = ops_since(&provider, before).await;
        assert!(ops.iter().all(|op| op["op"] == "fetch"), "{ops:?}");
        let RuntimeContentIdentityV1::Media(media) = &identity else {
            unreachable!()
        };
        let fetched: std::collections::BTreeSet<&str> =
            ops.iter().filter_map(|op| op["path"].as_str()).collect();
        for file in pcr::protected_content_files(media).unwrap() {
            assert!(
                fetched.contains(file.path.as_str()),
                "{} was fetched",
                file.path
            );
        }
    }

    #[tokio::test]
    async fn adopted_listing_with_tampered_file_is_refused() {
        let (_dir, registry, provider, identity, content_id) = published_media().await;
        {
            let mut files = provider.files.lock().await;
            let segment = files
                .keys()
                .find(|path| path.contains("segment"))
                .cloned()
                .expect("a published segment");
            files.get_mut(&segment).unwrap()[0] ^= 0x01;
        }
        assert!(pcr::verify_non_holder_content(
            registry.as_ref(),
            ContentAvailabilityTestProvider::CID,
            &content_id,
            &identity,
            pcr::NonHolderCheck::FullFetch,
            NOW,
        )
        .await
        .is_err());
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
            pcr::NonHolderCheck::FullFetch
        );
    }

    #[test]
    fn imported_listing_on_non_holder_is_unresolved() {
        let error = pcr::non_holder_check(pcr::PortableVerifyMode::Import).unwrap_err();
        assert!(pcr::RuntimeCustodyUnresolved::is(&error));
        // Buy, adoption and download answer it as `custody_elsewhere` (T4.7).
        assert!(pcr::RuntimeCustodyElsewhere::is(&error));
        assert_eq!(pcr::RuntimeCustodyUnresolved::CODE, "custody_unresolved");
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
        let source = include_str!("../protected_content_runtime.rs");
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
        let source = include_str!("../protected_content_runtime.rs");
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
            3,
            "declared, called by verify_runtime_portable_content and by adoption"
        );
    }
}

// Plan B T2.1: the Runtime starts one custody provider with every root.

#[cfg(unix)]
fn custody_status_with_roots(node_public_key_hex: &str) -> Value {
    let mut status = ProtectedStartupProvider::Custody.status();
    status["data"]["roots"] = json!([{
        "path": "inactive",
        "node_public_key": node_public_key_hex,
        "configured": true,
        "shares_held": 3,
    }]);
    status
}

#[cfg(unix)]
#[tokio::test]
async fn custody_host_registration_passes_one_legacy_root() {
    // The custody-host profile keeps the legacy init: the root itself and
    // `extra: null`.
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    super::register_custody_host_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let init: Value = serde_json::from_str(
        fs::read_to_string(&request_log)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(init["op"], "init");
    assert_eq!(
        init["config"]["base_path"],
        Value::String(state_root.to_string_lossy().to_string())
    );
    assert!(init["config"]["extra"].is_null());
}

#[cfg(unix)]
#[test]
fn custody_roots_come_from_disk() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    assert!(super::custody_provider_root_paths(&data_dir)
        .unwrap()
        .is_empty());

    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    let pool_b = format!("pools/{}", "b".repeat(64));
    let pool_a = format!("pools/{}", "a".repeat(64));
    for dir in [
        "inactive",
        "pools",
        pool_b.as_str(),
        pool_a.as_str(),
        // Never roots: a tombstone (T2.3), a staging folder, a bad name.
        "pools/.removed-0000",
        "pools/.custody-provider-stage-1-00",
        "pools/ABCD",
    ] {
        owner_only_dir(&base.join(dir));
    }
    fs::write(
        base.join("pools").join("c".repeat(64)),
        b"a file, not a root",
    )
    .unwrap();
    assert_eq!(
        super::custody_provider_root_paths(&data_dir).unwrap(),
        vec!["inactive".to_string(), pool_a.clone(), pool_b.clone()]
    );

    // A Home that serves only `pools/<hex>` roots still has roots.
    fs::remove_dir(base.join("inactive")).unwrap();
    assert_eq!(
        super::custody_provider_root_paths(&data_dir).unwrap(),
        vec![pool_a, pool_b]
    );
}

#[cfg(unix)]
#[test]
fn custody_status_check_accepts_the_private_root_list() {
    let key = format!("0x{}", "11".repeat(32));
    super::require_custody_provider_status(&custody_status_with_roots(&key)).unwrap();
    // A provider without roots (older build) still passes.
    super::require_custody_provider_status(&ProtectedStartupProvider::Custody.status()).unwrap();
    // A malformed root entry is refused.
    for root in [
        json!({"path": "inactive", "node_public_key": key, "configured": true}),
        json!({"path": "inactive", "node_public_key": key, "configured": true, "shares_held": 1, "more": 1}),
        json!({"path": 7, "node_public_key": key, "configured": true, "shares_held": 1}),
        json!({"path": "inactive", "node_public_key": key, "configured": "yes", "shares_held": 1}),
    ] {
        let mut status = ProtectedStartupProvider::Custody.status();
        status["data"]["roots"] = json!([root]);
        assert!(
            super::require_custody_provider_status(&status).is_err(),
            "{root}"
        );
    }
    let mut status = ProtectedStartupProvider::Custody.status();
    status["data"]["roots"] = json!({"path": "inactive"});
    assert!(super::require_custody_provider_status(&status).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn public_status_never_lists_roots() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let key = format!("0x{}", "5a".repeat(32));
    let (binary, _pid_file, _request_log) =
        write_mock_custody_provider_with_status(temp.path(), &custody_status_with_roots(&key));
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let status = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "status",
        json!({"op": "status"}),
    )
    .await
    .unwrap();
    assert_eq!(status["provider"], "custody");
    assert!(status.get("roots").is_none());
    let encoded = status.to_string();
    assert!(!encoded.contains(&key));
    assert!(!encoded.contains("shares_held"));
    assert!(!encoded.contains("inactive"));
}

#[cfg(unix)]
#[tokio::test]
async fn custody_registration_names_an_unsafe_root_and_starts_the_others() {
    // User decision 2026-11-12 10:26: an unsafe root follows the per-root rule.
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let pool = format!("pools/{}", "e".repeat(64));
    let unsafe_root = state_root.parent().unwrap().join(&pool);
    owner_only_dir(&unsafe_root);
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o755)).unwrap();
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let init: Value = serde_json::from_str(
        fs::read_to_string(&request_log)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        init["config"]["extra"]["roots"],
        json!([{"path": "inactive"}, {"path": pool}])
    );
}

/// A custody provider stand-in that answers `init` and `status` alike with a
/// status listing one configured root per `"path"` in the last init it was
/// sent, and logs every frame.
#[cfg(unix)]
fn write_mock_root_set_custody_provider(root: &Path) -> (PathBuf, PathBuf) {
    let binary = root.join("mock-root-set-custody-provider.sh");
    let request_log = root.join("mock-root-set-custody-provider.requests");
    let base = ProtectedStartupProvider::Custody.status();
    let data = base["data"].clone();
    let script = format!(
        "#!/bin/sh\nset -eu\nroots='[]'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{log}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"op\":\"init\"'*) roots=$(printf '%s' \"$line\" | sed -n 's/.*\"roots\":\\(\\[[^]]*\\]\\).*/\\1/p' | sed 's/{{\"path\":\\(\"[^\"]*\"\\)}}/{{\"path\":\\1,\"node_public_key\":null,\"configured\":true,\"shares_held\":0}}/g'); [ -n \"$roots\" ] || roots='[]' ;;\n  esac\n  case \"$line\" in\n    *'\"op\":\"init\"'*|*'\"op\":\"status\"'*) printf '{{\"status\":\"ok\",\"data\":{{\"provider\":\"{provider}\",\"version\":\"{version}\",\"configured\":true,\"supported_operations\":%s,\"request_schema\":\"{request}\",\"response_schema\":\"{response}\",\"roots\":%s}}}}\\n' '{ops}' \"$roots\" ;;\n    *) printf '%s\\n' '{{\"status\":\"ok\",\"data\":{{}}}}' ;;\n  esac\ndone\n",
        log = request_log.display(),
        provider = data["provider"].as_str().unwrap(),
        version = data["version"].as_str().unwrap(),
        request = data["request_schema"].as_str().unwrap(),
        response = data["response_schema"].as_str().unwrap(),
        ops = data["supported_operations"],
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, request_log)
}

#[cfg(unix)]
#[tokio::test]
async fn new_root_reaches_the_running_provider_without_restart() {
    // Plan B T2.2 (S2-Q1, user decision 2026-11-12 10:35): the server keeps
    // the custody bridge and sends a fresh init; no registry change.
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let (binary, request_log) = write_mock_root_set_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let pool = format!("pools/{}", "c".repeat(64));
    assert!(!super::custody_root_loaded(&data_dir, &pool).await);

    owner_only_dir(&state_root.parent().unwrap().join(&pool));
    let roots = super::refresh_custody_roots(&data_dir).await.unwrap();
    assert_eq!(
        roots
            .iter()
            .map(|root| root.path.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["inactive".to_string(), pool.clone()]
    );
    assert!(super::custody_root_loaded(&data_dir, &pool).await);
    assert!(super::custody_root_loaded(&data_dir, "inactive").await);
    // The same process: one spawn, a second init with both roots.
    let inits: Vec<Value> = fs::read_to_string(&request_log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|request| request["op"] == "init")
        .collect();
    assert_eq!(inits.len(), 2);
    assert_eq!(
        inits[1]["config"]["extra"]["roots"],
        json!([{"path": "inactive"}, {"path": pool}])
    );
    assert!(
        registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );
}

/// S2-F1: the mock root-set provider, where `init` answers an error while
/// `refuse_init` exists, and `shutdown` exits with `shutdown_exit`.
#[cfg(unix)]
fn write_failing_root_set_custody_provider(
    root: &Path,
    refuse_init: &Path,
    shutdown_exit: u8,
) -> PathBuf {
    let (plain, _) = write_mock_root_set_custody_provider(root);
    let script = fs::read_to_string(&plain).unwrap();
    let log_line_end = script.find("\n  case ").unwrap();
    let mut script = format!(
        "{}\n  case \"$line\" in *'\"op\":\"init\"'*) if [ -e '{}' ]; then printf '%s\\n' '{{\"status\":\"error\",\"code\":\"init_failed\",\"message\":\"refused\"}}'; continue; fi ;; esac{}",
        &script[..log_line_end],
        refuse_init.display(),
        &script[log_line_end..],
    );
    script = script.replacen("exit 0 ;;", &format!("exit {shutdown_exit} ;;"), 1);
    let binary = root.join("failing-root-set-custody-provider.sh");
    crate::test_support::write_from_child(&binary, &script, 0o700);
    binary
}

#[cfg(unix)]
fn plant_served_entry(data_dir: &Path, hex: &str) {
    crate::custody_consent::update_served_pools(data_dir, |pools| {
        pools.entries.insert(
            format!("sha256:{hex}"),
            crate::custody_consent::ServedPoolEntryV2 {
                owner_home: "did:key:z6MkOwner".to_string(),
                consent: crate::custody_consent::ServedConsentV2 {
                    term_days: 365,
                    signing_key_fingerprint_full: format!("sha256:{hex}"),
                },
                root_path: format!("pools/{hex}"),
                admin_profile_did: Some("did:key:z6MkAdmin".to_string()),
                pool_did: None,
                served_pool: None,
                descriptor: None,
            },
        );
        Ok(())
    })
    .unwrap();
}

#[cfg(unix)]
fn refusal_code(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<crate::custody_pool_setup::CustodyRefusal>()
        .unwrap_or_else(|| panic!("expected a custody refusal, got {error:#}"))
        .code()
}

/// S2-F1: with several roots, a refresh the provider refuses leaves the
/// pool served and reports the failure; a later retry stops it, and the
/// provider then holds only the roots left.
#[cfg(unix)]
#[tokio::test]
async fn stop_serving_reports_a_failed_refresh_and_a_retry_finishes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    for dir in [
        base.parent().unwrap().to_path_buf(),
        base.clone(),
        base.join("pools"),
    ] {
        owner_only_dir(&dir);
    }
    let (kept, stopped) = ("a".repeat(64), "b".repeat(64));
    for hex in [&kept, &stopped] {
        owner_only_dir(&base.join(format!("pools/{hex}")));
        plant_served_entry(&data_dir, hex);
    }
    let refuse = temp.path().join("refuse-init");
    let binary = write_failing_root_set_custody_provider(temp.path(), &refuse, 0);
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let stopped_path = format!("pools/{stopped}");
    assert!(super::custody_root_loaded(&data_dir, &stopped_path).await);

    fs::write(&refuse, b"").unwrap();
    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::stop_serving_pool(
        &write,
        &data_dir,
        Some(&registry),
        &stopped,
        100,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal_code(&error), "stop_failed");
    // Still served, and truthfully so: the provider still holds the root.
    assert!(crate::custody_consent::served_pools(&data_dir)
        .unwrap()
        .entries
        .contains_key(&format!("sha256:{stopped}")));
    assert!(super::custody_root_loaded(&data_dir, &stopped_path).await);

    fs::remove_file(&refuse).unwrap();
    crate::custody_pool_setup::stop_serving_pool(&write, &data_dir, Some(&registry), &stopped, 101)
        .await
        .unwrap();
    assert!(!crate::custody_consent::served_pools(&data_dir)
        .unwrap()
        .entries
        .contains_key(&format!("sha256:{stopped}")));
    assert!(!super::custody_root_loaded(&data_dir, &stopped_path).await);
    assert!(super::custody_root_loaded(&data_dir, &format!("pools/{kept}")).await);
    assert!(!base.join(&stopped_path).exists());
}

/// S2-F1: on the last root, a provider that does not stop cleanly leaves the
/// pool served and the root in place; a later retry stops it.
#[cfg(unix)]
#[tokio::test]
async fn stop_serving_the_last_root_reports_a_failed_unregister_and_a_retry_finishes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    for dir in [
        base.parent().unwrap().to_path_buf(),
        base.clone(),
        base.join("pools"),
    ] {
        owner_only_dir(&dir);
    }
    let only = "c".repeat(64);
    let root = base.join(format!("pools/{only}"));
    owner_only_dir(&root);
    plant_served_entry(&data_dir, &only);
    let binary =
        write_failing_root_set_custody_provider(temp.path(), &temp.path().join("never"), 1);
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::stop_serving_pool(
        &write,
        &data_dir,
        Some(&registry),
        &only,
        100,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal_code(&error), "stop_failed");
    assert!(crate::custody_consent::served_pools(&data_dir)
        .unwrap()
        .entries
        .contains_key(&format!("sha256:{only}")));
    assert!(root.is_dir(), "the root stays until the provider is out");

    crate::custody_pool_setup::stop_serving_pool(&write, &data_dir, Some(&registry), &only, 101)
        .await
        .unwrap();
    assert!(crate::custody_consent::served_pools(&data_dir)
        .unwrap()
        .entries
        .is_empty());
    assert!(!root.exists());
    assert!(
        !registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );
}

/// S2-F1: Remove on a serving Home whose provider refuses the refresh keeps
/// this Home's node and reports the failure; a later retry removes it and
/// the provider then holds only the served root.
#[cfg(unix)]
#[tokio::test]
async fn remove_reports_a_failed_refresh_and_a_retry_finishes() {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    crate::host_trust::seed_for_test(&data_dir, true);
    elastos_identity::load_or_create_device_key(&data_dir).unwrap();
    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    for dir in [
        base.parent().unwrap().to_path_buf(),
        base.clone(),
        base.join("pools"),
    ] {
        owner_only_dir(&dir);
    }
    let (own, served) = (
        format!("pools/{}", "d".repeat(64)),
        format!("pools/{}", "e".repeat(64)),
    );
    owner_only_dir(&base.join(&own));
    owner_only_dir(&base.join(&served));
    crate::collaboration_config::create_owner_only_file(
        &base.join(&own).join("trusted-runtime-issuer"),
        crate::protected_content_config::runtime_issuer_hex(&data_dir)
            .unwrap()
            .as_bytes(),
        "test issuer",
    )
    .unwrap();
    crate::custody_pool_setup::tests::write_local_node(&data_dir, "Home", "Paris");
    let node_file = crate::custody_pool_setup::local_node_path(&data_dir);
    assert!(node_file.exists());
    let refuse = temp.path().join("refuse-init");
    let binary = write_failing_root_set_custody_provider(temp.path(), &refuse, 0);
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    assert!(super::custody_root_loaded(&data_dir, &own).await);

    fs::write(&refuse, b"").unwrap();
    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap_err();
    assert_eq!(refusal_code(&error), "remove_failed");
    assert!(
        node_file.exists(),
        "this Home's node stays until the provider is out"
    );
    assert!(super::custody_root_loaded(&data_dir, &own).await);

    fs::remove_file(&refuse).unwrap();
    crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap();
    assert!(!node_file.exists());
    assert!(!super::custody_root_loaded(&data_dir, &own).await);
    assert!(super::custody_root_loaded(&data_dir, &served).await);
}

/// A custody target this server did not start (no remembered bridge) whose
/// first shutdown fails, so the registry keeps it Settling.
struct SettlingCustodyProvider {
    refuse_shutdown: AtomicBool,
}

#[async_trait::async_trait]
impl Provider for SettlingCustodyProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("invoke-only".to_string()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["custody"]
    }

    fn name(&self) -> &'static str {
        "custody"
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        if self.refuse_shutdown.swap(false, Ordering::SeqCst) {
            return Err(ProviderError::Provider(
                "shutdown did not finish".to_string(),
            ));
        }
        Ok(())
    }
}

/// A serving Home whose Remove stopped after its own root went to the
/// tombstone: the node file and the tombstone are left.
#[cfg(unix)]
fn interrupted_removal_home(
    with_served_root: bool,
) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    crate::host_trust::seed_for_test(&data_dir, true);
    elastos_identity::load_or_create_device_key(&data_dir).unwrap();
    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    for dir in [
        base.parent().unwrap().to_path_buf(),
        base.clone(),
        base.join("pools"),
    ] {
        owner_only_dir(&dir);
    }
    if with_served_root {
        owner_only_dir(&base.join(format!("pools/{}", "e".repeat(64))));
    }
    let tombstone = base.join(format!("pools/{}.removing", "d".repeat(64)));
    owner_only_dir(&tombstone);
    crate::custody_pool_setup::tests::write_local_node(&data_dir, "Home", "Paris");
    let node_file = crate::custody_pool_setup::local_node_path(&data_dir);
    (temp, data_dir, node_file, tombstone)
}

/// dkms-reviewer S2-F1: while the provider is Settling (its shutdown did not
/// finish), an interrupted removal with no root left is not reported
/// complete; the tombstone and node file stay, and a retry once the provider
/// is out finishes it.
#[cfg(unix)]
#[tokio::test]
async fn interrupted_removal_is_not_complete_while_the_provider_is_settling() {
    let (temp, data_dir, node_file, tombstone) = interrupted_removal_home(false);
    let binary =
        write_failing_root_set_custody_provider(temp.path(), &temp.path().join("never"), 1);
    // Boot saw the own root, so the provider runs; then the removal set the
    // root aside and the provider's shutdown did not finish.
    let own = tombstone.with_file_name("d".repeat(64));
    fs::rename(&tombstone, &own).unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    fs::rename(&own, &tombstone).unwrap();
    assert!(registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .is_err());
    assert!(
        registry
            .has_runtime_provider_target_registration(CUSTODY_PROVIDER_ID)
            .await
    );
    assert!(
        !registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );

    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap_err();
    assert_eq!(refusal_code(&error), "remove_failed");
    assert!(node_file.exists());
    assert!(tombstone.exists());

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap();
    assert!(!node_file.exists());
    assert!(!tombstone.exists());
}

/// dkms-reviewer S2-F1: with a custody target this server cannot refresh (no
/// remembered bridge) still registered, Settling, an interrupted removal is
/// not reported complete; once the target is gone a retry finishes it.
#[cfg(unix)]
#[tokio::test]
async fn interrupted_removal_is_not_complete_while_an_unknown_bridge_target_is_settling() {
    let (_temp, data_dir, node_file, tombstone) = interrupted_removal_home(true);
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_runtime_provider_target(
        registry.as_ref(),
        Arc::new(SettlingCustodyProvider {
            refuse_shutdown: AtomicBool::new(true),
        }),
    )
    .await
    .unwrap();
    assert!(!super::custody_bridge_known(&data_dir));
    assert!(registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .is_err());
    assert!(
        registry
            .has_runtime_provider_target_registration(CUSTODY_PROVIDER_ID)
            .await
    );

    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap_err();
    assert_eq!(refusal_code(&error), "remove_failed");
    assert!(node_file.exists());
    assert!(tombstone.exists());

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap();
    assert!(!node_file.exists());
    assert!(!tombstone.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn serves_only_pools_roots_and_still_starts_the_provider() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    let pool = format!("pools/{}", "d".repeat(64));
    owner_only_dir(&base.join(&pool));
    assert!(!inactive_custody_state_root(&data_dir).exists());
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    assert!(
        registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );
    let init: Value = serde_json::from_str(
        fs::read_to_string(&request_log)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(init["config"]["extra"]["roots"], json!([{"path": pool}]));
}

// ---------------------------------------------------------------------------
// OPEN-LOOP F3: one viewer reply contract for Runtime, Reader and Player
// ---------------------------------------------------------------------------

/// The checked-in viewer contract the Reader and Player tests parse too.
const VIEWER_CONTRACT: &str = include_str!("viewer_contract.json");

/// Values the contract fixes, not just their type.
const VIEWER_CONTRACT_CONSTANTS: [&str; 4] =
    ["schema", "content_kind", "encoding", "has_init_segment"];

/// The shape of a reply: every key with its value type, recursively, plus
/// the contract constants by value.
fn viewer_reply_shape(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| {
                    let shape = if VIEWER_CONTRACT_CONSTANTS.contains(&key.as_str()) {
                        field.clone()
                    } else {
                        viewer_reply_shape(field)
                    };
                    (key.clone(), shape)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(viewer_reply_shape).collect()),
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("bool"),
        Value::Null => json!("null"),
    }
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
        super::runtime_custody_viewer_response_for(identity, mint_id, &handle, 1234).unwrap()
    };
    let pool_open = |identity: &RuntimeContentIdentityV1| {
        super::runtime_custody_pool_viewer_response(identity, mint_id, &opened).unwrap()
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
            super::runtime_custody_viewer_object_part_response(mint_id, &handle_hex, 0, b"hello"),
        ),
        (
            "part",
            "media part",
            super::runtime_custody_viewer_media_part_response(mint_id, &handle_hex, b"init"),
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
        crate::auth::now_ts() - 2 * super::RUNTIME_CUSTODY_FINALITY_WATCH_SECS,
    );
    let latest = json!({
        "request_id": format!(
            "open-finality:{}:latest",
            hex::encode(harness.mint_id.as_bytes())
        ),
        "content_access_id": super::runtime_content_access_id_hex(mint.draft().content_access_id()),
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
        let error = super::open_runtime_custody_viewer(
            &harness.data_dir,
            harness.registry.clone(),
            super::RuntimeCustodyViewerOpenInput {
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
            .downcast_ref::<super::RuntimeCustodyOpenProgress>()
            .unwrap_or_else(|| panic!("a typed wait: {error:#}"));
        assert_eq!(progress.as_json()["stage"], "finalizing", "{error:#}");
        assert_eq!(progress.as_json()["resumable"], true);
    }
    assert_eq!(chain.requests().await.len(), 2 * POLLS);
    assert!(
        decrypt.requests().await.is_empty(),
        "nothing before the Wallet ran"
    );
    assert!(super::load_runtime_custody_viewer_record(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id()
    )
    .unwrap()
    .is_none());
}
