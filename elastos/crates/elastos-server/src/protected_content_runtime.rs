//! Protected-content Runtime provider plane.
//!
//! This module registers Runtime-owned `protect` and `custody` routes, scans
//! the durable Runtime release journal on startup, and evaluates policy through
//! the existing `chain` registry route. Library mint and buy use these seams.
//! It does not replace the provisional `key`/`rights`/`drm`/`decrypt`
//! open/share path or expose provider topology to capsules.

#[cfg(test)]
pub(crate) mod tests;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::{
    validate_custody_epoch_against_pool_at, CanonicalContract, ContentAccessIdV1,
    CustodyCommitteeAuthorizationIdentityV1, CustodyEnvelopeV1, CustodyEpochIssuerKeyV1, Digest32,
    EncryptedContentIdentityV1, KeyReleaseOutcomeV1, KeyReleaseRequestV1, NodeContributionRefV1,
    NodeCustodyPublicKeyV1, NodePublicKey, ProfileIdentityV1, RecipientKeyAuthorizationStatementV1,
    RecipientKeyIdentityV1, RecipientPublicKeyBytesV1, ReplayNonce16, RightsActionV1,
    RightsEvaluationEvidenceRequestV1, RightsPolicyBodyV1, RightsPolicyIdentityV1, RightsRequestV1,
    RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1, RuntimeReleaseOperationStatementV1,
    RuntimeSessionBindingV1, SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1,
    SignedCustodyPoolV1, SignedRuntimeReleaseOperationV1, SignedTerminalReceiptV1,
    TerminalReceiptIssuerKey, TerminalReceiptStatementV1, WalletSignedRightsRequestV1,
};
use elastos_protected_content_provider_contracts::{
    CencFmp4MediaIdentityV1, DecryptProviderRequestOpV1, DecryptProviderRequestV1,
    DecryptProviderResponseV1, ProtectProviderRequestV1, ProtectProviderResponseStatusV1,
    ProtectProviderResponseV1, ProtectionSessionNodeV1, RightsProviderRequestV1,
    RightsProviderResponseV1, ValidatedCencFmp4MediaSessionLayoutV1,
    ValidatedClearFmp4MediaSessionLayoutV1, ViewerMediaPartSelectorV1,
    CUSTODY_PROVIDER_REQUEST_SCHEMA_V1, CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1, DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
    MAX_PROTECT_MEDIA_SEGMENTS_V1, MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1,
    PROTECT_PROVIDER_REQUEST_SCHEMA_V1, PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
};
use elastos_protected_content_rights::{
    PrivateCustodyRightsRequestV1, CHAIN_PROVIDER_ID, CHAIN_RIGHTS_EVIDENCE_OP,
};
use elastos_protected_content_runtime::RuntimeProviderCallError;
use elastos_protected_content_runtime::{
    cancel_prepared_recipient, cancel_prepared_recipient_with_result_by_handle,
    close_viewer_session_with_result, open_viewer_session, prepare_recipient,
    read_viewer_media_part, resolve_runtime_mint_selected_nodes, PersistedRuntimeMint,
    PersistedRuntimeReleaseOperation, RuntimeContentAvailabilityRequirement,
    RuntimeCustodyTerminalKind, RuntimeDecryptProvider, RuntimeMediaPreparationRecord,
    RuntimeMediaPreparationState, RuntimeMintConfiguredCustodyProvider, RuntimeMintCoordinator,
    RuntimeMintCoordinatorError, RuntimeMintCoordinatorOutcome, RuntimeMintCreatorTerminalEvidence,
    RuntimeMintDraft, RuntimeMintIntent, RuntimeMintJournal, RuntimeOpenViewerSessionInput,
    RuntimePreparedRecipient, RuntimePreparedRecipientCancelResult,
    RuntimeProtectedContentPurchaseIntent, RuntimePurchaseEffectAuthority,
    RuntimeReleaseAuditRecord, RuntimeReleaseCoordinator, RuntimeReleaseCoordinatorOutcome,
    RuntimeReleaseJournal, RuntimeReleaseJournalError, RuntimeReleaseTerminalResult,
    RuntimeSelectedProvider, RuntimeVerifiedContentAvailability, RuntimeVerifiedPurchaseEffect,
    RuntimeViewerSession, RuntimeViewerSessionCloseResult,
};
use elastos_runtime::provider::bridge::{ProviderBridge, ProviderConfig};
use elastos_runtime::provider::{
    Provider, ProviderCarrierRoute, ProviderError, ProviderInvocation, ProviderInvocationTransport,
    ProviderRegistry, ProviderTransfer, ResourceRequest, ResourceResponse,
};
use elastos_wallet_contract::{
    ValidatedChainOutcomeBindingV1, VerifiedWalletInvocationContext, WalletProviderOperationV2,
    WalletProviderRequestV2, MAX_INVOCATION_TTL_SECS, WALLET_BUS_OPERATION,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest as _;

/// Protected content (Elacity Player, Protect and List, Marketplace Media)
/// ships after 0.8.0 (#91). It stays off, and Home hides those surfaces and
/// refuses protected publishing, unless the host sets
/// `elastos config set protected_content true`.
pub(crate) fn protected_content_enabled(data_dir: &Path) -> bool {
    fs::read_to_string(data_dir.join("config.toml"))
        .ok()
        .and_then(|contents| contents.parse::<toml::Table>().ok())
        .and_then(|config| {
            config
                .get("protected_content")
                .and_then(toml::Value::as_bool)
        })
        .unwrap_or(false)
}

pub(crate) const PROTECT_PROVIDER_ID: &str = "protect";
pub(crate) const MEDIA_PROVIDER_ID: &str = "media";
pub(crate) const RUNTIME_PROVIDER_ID: &str = "runtime";
pub(crate) const PROTECTED_CONTENT_DECRYPT_PROVIDER_ID: &str = "protected-content-decrypt";
const CONTENT_PROVIDER_ID: &str = "content";
const PROTECTED_CONTENT_REPLICATION_POLICY: &str = "protected-content-replication/v1";
const PROTECTED_CONTENT_MIN_REPLICAS: u32 = 3;
const PROTECTED_CONTENT_REQUIRE_LIVE_MULTI_PEER_PROOF: bool = true;
const PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS: u64 = 60;
const PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS: u64 = 5;

pub(crate) const RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE: &str =
    "Runtime custody composition is not configured";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE: &str =
    "Runtime custody purchase is pending exact Wallet or Chain settlement";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody purchase is unavailable";
pub(crate) const RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody content availability is unavailable";
pub(crate) const RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody viewer release approval is unavailable";

/// Fail-closed mapping for the viewer release path: logs the cause and source
/// line at warn and keeps the stable message outermost while carrying the
/// cause chain (surfaced as the library error `detail`).
macro_rules! release_unavailable {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody viewer release failed closed"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE)
        }
    };
}

macro_rules! release_unavailable_missing {
    () => {
        || {
            tracing::warn!(
                line = line!(),
                "Runtime custody viewer release failed closed"
            );
            anyhow::anyhow!("{}:{}", file!(), line!())
                .context(RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE)
        }
    };
}

mod creator;
mod custody;
mod library_publish;
mod listing;
mod viewer;

pub use self::creator::*;
pub use self::custody::*;
pub use self::library_publish::*;
pub(crate) use self::listing::*;
pub use self::viewer::*;

const PROTECTED_CONTENT_ROOT: &str = "protected-content";
const CUSTODY_COMPOSITION_CONFIG_FILE: &str = "protected-content/custody-composition.json";
const RUNTIME_MINT_JOURNAL_ROOT: &str = "protected-content/runtime-mint";
const RUNTIME_OPEN_MATERIAL_ROOT: &str = "protected-content/runtime-open";
const RUNTIME_LISTING_ROOT: &str = "protected-content/runtime-listings";
const RUNTIME_PURCHASE_ROOT: &str = "protected-content/runtime-purchases";
pub(crate) const RUNTIME_PURCHASE_SCHEMA_V1: &str = "elastos.library.runtime-custody-purchase/v1";
const MAX_CUSTODY_COMPOSITION_PEER_DID_BYTES: usize = 256;
const PROTECTED_CONTENT_OBJECT_KIND: &str = "protected-content";
const PROTECTED_CONTENT_IDENTITY_PATH: &str = "protected-content/v1/identity.bin";
const PROTECTED_CONTENT_INIT_PATH: &str = "protected-content/v1/init.mp4";
const PROTECTED_CONTENT_SEGMENTS_PREFIX: &str = "protected-content/v1/segments/";
const PROTECTED_CONTENT_SEGMENTS_SUFFIX: &str = ".m4s";
const PROTECTED_CONTENT_AVAILABLE_STATUS: &str = "network_available";
const CONTENT_AVAILABILITY_RECEIPT_SCHEMA: &str = "elastos.content.availability.receipt/v1";
const CONTENT_AVAILABILITY_RECEIPT_DOMAIN: &str = "elastos.content.availability.receipt.v1";
const MEDIA_PROVIDER_PROCESS_ID: &str = "media-provider";
const INACTIVE_CUSTODY_ROOT: &str = "protected-content/custody-provider/inactive";
const MEDIA_PROVIDER_PREPARED_MEDIA_SCHEMA_V1: &str = "elastos.media-provider.prepared-media/v1";
const MEDIA_PROVIDER_OUTPUT_MIME_TYPE_V1: &str = "video/mp4";
const MEDIA_PROVIDER_OUTPUT_CODECS_V1: &str = "avc1.640028";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePreparedMediaProviderOutput {
    schema: String,
    mime_type: String,
    codecs: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyCompositionConfigFile {
    pub(crate) schema: String,
    pub(crate) expected_policy_authority_base64: String,
    pub(crate) expected_committee_authorization_identity_base64: String,
    pub(crate) signed_pool_base64: String,
    pub(crate) signed_epoch_base64: String,
    pub(crate) signed_committee_authorization_base64: String,
    pub(crate) routes: Vec<RuntimeCustodyRouteBindingConfig>,
}

#[async_trait::async_trait]
impl elastos_protected_content_runtime::RuntimeRightsProvider for RuntimeCustodyRegistryAdapter {
    async fn evaluate_rights(
        &self,
        request: &RightsProviderRequestV1,
    ) -> Result<RightsProviderResponseV1, RuntimeProviderCallError> {
        self.invoke_rights(request).await
    }
}

#[async_trait::async_trait]
impl elastos_protected_content_runtime::RuntimeCustodyProvider for RuntimeCustodyRegistryAdapter {
    async fn release_contribution(
        &self,
        request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_custody("release_contribution", request).await
    }

    async fn provision_node_share(
        &self,
        request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_custody("provision_node_share", request).await
    }
}

pub fn runtime_release_journal(data_dir: &Path) -> RuntimeReleaseJournal {
    RuntimeReleaseJournal::new(data_dir.join("protected-content").join("runtime-release"))
}

pub fn list_unresolved_runtime_releases(
    data_dir: &Path,
) -> Result<Vec<PersistedRuntimeReleaseOperation>, RuntimeReleaseJournalError> {
    runtime_release_journal(data_dir).list_unresolved()
}

pub fn unresolved_release_audit_records(
    data_dir: &Path,
) -> Result<Vec<RuntimeReleaseAuditRecord>, RuntimeReleaseJournalError> {
    list_unresolved_runtime_releases(data_dir)?
        .iter()
        .map(PersistedRuntimeReleaseOperation::audit_record)
        .collect()
}

/// Derive the Runtime operation issuer custody and decrypt providers must
/// trust for the Runtime rooted at this device key.
pub fn derive_protected_content_runtime_issuer(
    device_key: &[u8; 32],
) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
    let (runtime_signing_key, _) = elastos_identity::derive_did(device_key);
    RuntimeOperationIssuerKeyV1::new(runtime_signing_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("active Runtime operation issuer is invalid"))
}

pub(crate) fn protected_content_root(data_dir: &Path) -> PathBuf {
    data_dir.join(PROTECTED_CONTENT_ROOT)
}

fn invalid_inactive_custody_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("inactive custody provider configuration is missing or unsafe: {reason}")
}

pub(crate) fn validate_owner_only_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let _ = error;
        invalid_inactive_custody_config(format!("{label} is unavailable"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "{}",
            invalid_inactive_custody_config(format!("{label} must be an owner-only directory"))
        );
    }
    validate_owner_only_metadata_with_error(
        label,
        &metadata,
        false,
        invalid_inactive_custody_config,
    )
}

#[cfg(unix)]
fn validate_owner_only_metadata_with_error(
    label: &str,
    metadata: &fs::Metadata,
    require_single_link: bool,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode() & 0o777;
    let expected_mask = if metadata.is_dir() { 0o700 } else { 0o600 };
    if metadata.uid() != unsafe { libc::geteuid() } || mode & 0o077 != 0 {
        anyhow::bail!("{}", error_fn(format!("{label} must be owner-only")));
    }
    if require_single_link && metadata.nlink() != 1 {
        anyhow::bail!("{}", error_fn(format!("{label} must not be hard-linked")));
    }
    if mode == 0 {
        anyhow::bail!("{}", error_fn(format!("{label} must not be inaccessible")));
    }
    if mode & expected_mask != mode {
        anyhow::bail!(
            "{}",
            error_fn(format!("{label} has an unsupported owner mode"))
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_metadata_with_error(
    _label: &str,
    _metadata: &fs::Metadata,
    _require_single_link: bool,
    _error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<()> {
    anyhow::bail!("owner-only protected-content config validation is unsupported on this platform")
}

fn invalid_custody_composition_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("protected-content custody composition config is missing or unsafe: {reason}")
}

fn validate_owner_only_protected_content_dir_with_error(
    data_dir: &Path,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<PathBuf> {
    let root = protected_content_root(data_dir);
    let metadata = fs::symlink_metadata(&root)
        .map_err(|_| error_fn("protected-content parent is unavailable".to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "{}",
            error_fn("protected-content parent must be an owner-only directory".to_string())
        );
    }
    validate_owner_only_metadata_with_error(
        "protected-content parent",
        &metadata,
        false,
        error_fn,
    )?;
    Ok(root)
}

fn invalid_media_provider_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("media-provider private config is missing or unsafe: {reason}")
}

#[cfg(unix)]
fn read_owner_only_protected_content_config_bytes(
    path: &Path,
    max_bytes: usize,
    label: &str,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|_| error_fn(format!("{label} is unavailable")))?;
    let metadata = file
        .metadata()
        .map_err(|_| error_fn(format!("{label} metadata is unavailable")))?;
    if !metadata.is_file() {
        anyhow::bail!("{}", error_fn(format!("{label} must be a regular file")));
    }
    validate_owner_only_metadata_with_error(label, &metadata, true, error_fn)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    std::io::Read::by_ref(&mut file)
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        anyhow::bail!("{}", error_fn(format!("{label} exceeds bounds")));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_owner_only_protected_content_config_bytes(
    path: &Path,
    max_bytes: usize,
    label: &str,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<Vec<u8>> {
    let _ = (path, max_bytes, label, error_fn);
    anyhow::bail!("owner-only protected-content config validation is unsupported on this platform")
}

fn decode_canonical_base64_bytes(
    encoded: &str,
    max_decoded_bytes: usize,
    field: &str,
) -> anyhow::Result<Vec<u8>> {
    let max_encoded_bytes = max_decoded_bytes.div_ceil(3) * 4;
    if encoded.is_empty() || encoded.len() > max_encoded_bytes {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config(format!("{field} base64 has invalid length"))
        );
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid_custody_composition_config(format!("{field} base64 is invalid")))?;
    if decoded.is_empty()
        || decoded.len() > max_decoded_bytes
        || base64::engine::general_purpose::STANDARD.encode(&decoded) != encoded
    {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config(format!("{field} base64 is not canonical"))
        );
    }
    Ok(decoded)
}

pub fn log_unresolved_runtime_releases(data_dir: &Path) {
    match list_unresolved_runtime_releases(data_dir) {
        Ok(operations) => {
            let effect_started = operations
                .iter()
                .filter(|operation| operation.provider_effect_started())
                .count();
            if operations.is_empty() {
                return;
            }
            tracing::warn!(
                unresolved = operations.len(),
                effect_started,
                "protected-content runtime release journal has unresolved operations; Runtime will not infer completion from absence or elapsed time"
            );
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "protected-content runtime release journal scan failed closed"
            );
        }
    }
}

pub(crate) async fn invoke_json_provider(
    registry: &ProviderRegistry,
    target: &str,
    op: &str,
    request: Value,
) -> Result<Value, String> {
    invoke_json_provider_with_transport(
        registry,
        target,
        op,
        request,
        ProviderInvocationTransport::Local,
    )
    .await
}

pub(crate) async fn invoke_json_provider_with_transport(
    registry: &ProviderRegistry,
    target: &str,
    op: &str,
    request: Value,
    transport: ProviderInvocationTransport,
) -> Result<Value, String> {
    let response = registry
        .invoke_provider(ProviderInvocation {
            source: RUNTIME_PROVIDER_ID.to_string(),
            target: target.to_string(),
            op: op.to_string(),
            request,
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport,
        })
        .await
        .map_err(|error| {
            tracing::warn!(
                %target,
                %op,
                error = %error,
                "provider invocation failed"
            );
            format!("{target} provider {op} invocation failed: {error}")
        })?;
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{target} provider {op} response is missing status"))?;
    match status {
        "ok" => response
            .get("data")
            .cloned()
            .ok_or_else(|| format!("{target} provider {op} response is missing data")),
        "error" => {
            // Keep the provider's own code/message: this string travels back
            // to the caller (over Carrier for a committee member) and is the
            // only trace of why a node refused.
            let code = response
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let message = response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            tracing::warn!(%target, %op, %code, %message, "provider rejected the request");
            Err(format!(
                "{target} provider {op} rejected the request: {code}: {message}"
            ))
        }
        _ => Err(format!(
            "{target} provider {op} response has unsupported status"
        )),
    }
}

pub(crate) fn runtime_protected_content_id(
    encrypted_content: &EncryptedContentIdentityV1,
) -> anyhow::Result<String> {
    Ok(format!(
        "content:{}",
        hex::encode(encrypted_content.canonical_hash()?.as_bytes())
    ))
}

fn validate_protected_content_availability_requirement(
    requirement: &RuntimeContentAvailabilityRequirement,
) -> anyhow::Result<()> {
    if requirement.policy() != PROTECTED_CONTENT_REPLICATION_POLICY
        || requirement.minimum_replicas() != PROTECTED_CONTENT_MIN_REPLICAS
    {
        anyhow::bail!("protected content availability requirement is invalid");
    }
    Ok(())
}

/// Re-observes availability for `content_cid` through the content plane's
/// `ensure` (local pin + Carrier replica proofs, signed into a new receipt
/// bound to the requirement's policy, object identity and publisher), then
/// returns that receipt. Nothing is republished.
async fn refresh_content_availability_receipt(
    registry: &ProviderRegistry,
    content_cid: &str,
    requirement: &RuntimeContentAvailabilityRequirement,
) -> anyhow::Result<Vec<u8>> {
    let response = registry
        .send_raw(
            CONTENT_PROVIDER_ID,
            &json!({
                "op": "ensure",
                "cid": content_cid,
                "availability_requirements": {
                    "min_replicas": requirement.minimum_replicas(),
                    "require_live_multi_peer_proof": PROTECTED_CONTENT_REQUIRE_LIVE_MULTI_PEER_PROOF,
                },
                "availability_policy": requirement.policy(),
                "object_did": requirement.expected_object_identity(),
                "publisher_did": requirement.expected_publisher_did(),
            }),
        )
        .await
        .map_err(|error| anyhow::anyhow!("protected content ensure is unavailable: {error}"))?;
    if response.get("status").and_then(Value::as_str) != Some("ok") {
        anyhow::bail!("protected content ensure is invalid");
    }
    fetch_content_availability_receipt(registry, content_cid).await
}

async fn fetch_content_availability_receipt(
    registry: &ProviderRegistry,
    content_cid: &str,
) -> anyhow::Result<Vec<u8>> {
    let response = registry
        .send_raw(
            CONTENT_PROVIDER_ID,
            &json!({ "op": "status", "cid": content_cid }),
        )
        .await
        .map_err(|error| anyhow::anyhow!("protected content status is unavailable: {error}"))?;
    if response.get("status").and_then(Value::as_str) != Some("ok") {
        anyhow::bail!("protected content status is invalid");
    }
    let receipt = response
        .get("data")
        .and_then(|data| data.get("receipt"))
        .ok_or_else(|| anyhow::anyhow!("protected content status receipt is absent"))?;
    serde_json::to_vec(receipt)
        .map_err(|_| anyhow::anyhow!("protected content status receipt is invalid"))
}

fn verify_protected_content_directory(
    directory: &Path,
    media_identity: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<()> {
    let expected_files = protected_content_files(media_identity)?;
    let expected_paths: Vec<String> = expected_files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    let actual_paths = protected_content_directory_files(directory)?;
    if actual_paths != expected_paths {
        anyhow::bail!("protected content directory layout is invalid");
    }
    let descriptor = fs::read(directory.join(PROTECTED_CONTENT_IDENTITY_PATH))
        .map_err(|_| anyhow::anyhow!("protected content descriptor is unavailable"))?;
    let canonical_identity = media_identity
        .canonical_bytes()
        .map_err(|_| anyhow::anyhow!("protected content media identity is invalid"))?;
    if descriptor != canonical_identity
        || CencFmp4MediaIdentityV1::from_canonical_bytes(&descriptor)
            .map_err(|_| anyhow::anyhow!("protected content descriptor is invalid"))?
            != *media_identity
    {
        anyhow::bail!("protected content descriptor is invalid");
    }
    let init = fs::read(directory.join(PROTECTED_CONTENT_INIT_PATH))
        .map_err(|_| anyhow::anyhow!("protected content init is unavailable"))?;
    let mut segments = Vec::with_capacity(media_identity.encrypted_segments().len());
    for index in 0..media_identity.encrypted_segments().len() {
        segments.push(
            fs::read(directory.join(protected_content_segment_path(index)))
                .map_err(|_| anyhow::anyhow!("protected content segment is unavailable"))?,
        );
    }
    let reconstructed = CencFmp4MediaIdentityV1::new_from_bytes(
        &init,
        &segments,
        media_identity.mime_type(),
        media_identity.codecs(),
    )
    .map_err(|_| anyhow::anyhow!("protected content media layout is invalid"))?;
    if reconstructed != *media_identity {
        anyhow::bail!("protected content media identity is invalid");
    }
    Ok(())
}

fn protected_content_directory_files(directory: &Path) -> anyhow::Result<Vec<String>> {
    let mut actual_paths = Vec::new();
    collect_protected_content_directory_files(directory, directory, &mut actual_paths)?;
    actual_paths.sort_unstable();
    Ok(actual_paths)
}

fn collect_protected_content_directory_files(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<String>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(directory)
        .map_err(|_| anyhow::anyhow!("protected content directory is unavailable"))?
    {
        let entry = entry.map_err(|_| anyhow::anyhow!("protected content directory is invalid"))?;
        let file_type = entry
            .file_type()
            .map_err(|_| anyhow::anyhow!("protected content directory is invalid"))?;
        if file_type.is_symlink() {
            anyhow::bail!("protected content directory is invalid");
        }
        if file_type.is_dir() {
            collect_protected_content_directory_files(root, &entry.path(), paths)?;
            continue;
        }
        if !file_type.is_file() {
            anyhow::bail!("protected content directory is invalid");
        }
        let entry_path = entry.path();
        let relative = entry_path
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("protected content directory is invalid"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("protected content directory is invalid"))?;
        let normalized = relative.replace('\\', "/");
        match normalized.as_str() {
            PROTECTED_CONTENT_IDENTITY_PATH | PROTECTED_CONTENT_INIT_PATH => {}
            _ if normalized.starts_with(PROTECTED_CONTENT_SEGMENTS_PREFIX)
                && normalized.ends_with(PROTECTED_CONTENT_SEGMENTS_SUFFIX) =>
            {
                let index = normalized
                    .strip_prefix(PROTECTED_CONTENT_SEGMENTS_PREFIX)
                    .and_then(|value| value.strip_suffix(PROTECTED_CONTENT_SEGMENTS_SUFFIX))
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or_else(|| {
                        anyhow::anyhow!("protected content directory layout is invalid")
                    })?;
                if normalized != protected_content_segment_path(index) {
                    anyhow::bail!("protected content directory layout is invalid");
                }
            }
            _ => anyhow::bail!("protected content directory layout is invalid"),
        }
        paths.push(normalized);
    }
    Ok(())
}

fn protected_content_files(
    media_identity: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<Vec<crate::content::ContentObjectFile>> {
    let descriptor = media_identity
        .canonical_bytes()
        .map_err(|_| anyhow::anyhow!("protected content media identity is invalid"))?;
    let mut files = Vec::with_capacity(media_identity.encrypted_segments().len() + 2);
    files.push(content_object_file(
        PROTECTED_CONTENT_IDENTITY_PATH,
        &descriptor,
    ));
    files.push(crate::content::ContentObjectFile {
        path: PROTECTED_CONTENT_INIT_PATH.to_string(),
        sha256: hex::encode(media_identity.init_segment_sha256().as_bytes()),
        size: media_identity.init_segment_bytes(),
    });
    files.extend(
        media_identity
            .encrypted_segments()
            .iter()
            .enumerate()
            .map(|(index, segment)| crate::content::ContentObjectFile {
                path: protected_content_segment_path(index),
                sha256: hex::encode(segment.ciphertext_sha256().as_bytes()),
                size: segment.ciphertext_bytes(),
            }),
    );
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn content_object_file(path: &str, bytes: &[u8]) -> crate::content::ContentObjectFile {
    crate::content::ContentObjectFile {
        path: path.to_string(),
        sha256: hex::encode(sha2::Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}

fn protected_content_segment_path(index: usize) -> String {
    format!("{PROTECTED_CONTENT_SEGMENTS_PREFIX}{index:08}{PROTECTED_CONTENT_SEGMENTS_SUFFIX}")
}

async fn verify_protected_content_manifest_and_files(
    registry: &ProviderRegistry,
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    media_identity: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let expected_files = protected_content_files(media_identity)?;
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != PROTECTED_CONTENT_OBJECT_KIND
        || !manifest.links.is_empty()
        || !content_object_files_match(&manifest.files, &expected_files)
        || manifest.content_digest != content_object_digest(&expected_files)
    {
        anyhow::bail!("protected content object manifest is invalid");
    }
    let mut protected_init = None;
    let mut encrypted_segments = Vec::with_capacity(media_identity.encrypted_segments().len());
    for file in &expected_files {
        let bytes =
            crate::content::fetch_bytes_via_provider(registry, content_cid, Some(&file.path))
                .await?;
        crate::content::verify_content_object_file(content_cid, file, &bytes)?;
        match file.path.as_str() {
            PROTECTED_CONTENT_IDENTITY_PATH => {
                let canonical_identity = media_identity
                    .canonical_bytes()
                    .map_err(|_| anyhow::anyhow!("protected content media identity is invalid"))?;
                if bytes != canonical_identity
                    || CencFmp4MediaIdentityV1::from_canonical_bytes(&bytes)
                        .map_err(|_| anyhow::anyhow!("protected content descriptor is invalid"))?
                        != *media_identity
                {
                    anyhow::bail!("protected content descriptor is invalid");
                }
            }
            PROTECTED_CONTENT_INIT_PATH => protected_init = Some(bytes),
            _ => encrypted_segments.push(bytes),
        }
    }
    let protected_init =
        protected_init.ok_or_else(|| anyhow::anyhow!("protected content init is absent"))?;
    let reconstructed = CencFmp4MediaIdentityV1::new_from_bytes(
        &protected_init,
        &encrypted_segments,
        media_identity.mime_type(),
        media_identity.codecs(),
    )
    .map_err(|_| anyhow::anyhow!("protected content media layout is invalid"))?;
    if reconstructed != *media_identity {
        anyhow::bail!("protected content media identity is invalid");
    }
    Ok((protected_init, encrypted_segments))
}

fn content_object_files_match(
    actual: &[crate::content::ContentObjectFile],
    expected: &[crate::content::ContentObjectFile],
) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.path == expected.path
                && actual.sha256 == expected.sha256
                && actual.size == expected.size
        })
}

fn content_object_digest(files: &[crate::content::ContentObjectFile]) -> String {
    let mut hasher = sha2::Sha256::new();
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(file.sha256.as_bytes());
        hasher.update(b"\0");
        hasher.update(file.size.to_string().as_bytes());
        hasher.update(b"\0");
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn decode_0x_hex(value: &str) -> Option<Vec<u8>> {
    let hex = value.strip_prefix("0x")?;
    hex::decode(hex).ok()
}

fn verify_protected_content_receipt(
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    receipt_json: &[u8],
    media_identity: &CencFmp4MediaIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: u64,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    cid::Cid::try_from(content_cid)
        .map_err(|_| anyhow::anyhow!("protected content availability CID is invalid"))?;
    let receipt: crate::content::SignedAvailabilityReceipt =
        serde_json::from_slice(receipt_json)
            .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    let receipt_json = serde_json::to_vec(&receipt)
        .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    if receipt.payload.schema != CONTENT_AVAILABILITY_RECEIPT_SCHEMA
        || receipt.signer_did != requirement.expected_provider_did()
        || receipt.payload.cid != content_cid
        || receipt.payload.uri != format!("elastos://{content_cid}")
        || receipt.payload.object_did.as_deref() != Some(requirement.expected_object_identity())
        || receipt.payload.publisher_did != requirement.expected_publisher_did()
        || receipt.payload.policy != requirement.policy()
        || receipt.payload.status != PROTECTED_CONTENT_AVAILABLE_STATUS
        || receipt.payload.replicas < requirement.minimum_replicas()
        || (PROTECTED_CONTENT_REQUIRE_LIVE_MULTI_PEER_PROOF
            && receipt
                .payload
                .peer_selection
                .get("live_multi_peer_proof")
                .and_then(Value::as_bool)
                != Some(true))
        || manifest.object_did.as_deref() != Some(requirement.expected_object_identity())
        || manifest.publisher_did.as_deref() != Some(requirement.expected_publisher_did())
    {
        anyhow::bail!("protected content availability receipt binding is invalid");
    }
    let max_checked_at = now_unix_seconds
        .checked_add(requirement.max_future_skew_seconds())
        .ok_or_else(|| anyhow::anyhow!("protected content availability time is invalid"))?;
    if receipt.payload.checked_at > max_checked_at
        || now_unix_seconds.saturating_sub(receipt.payload.checked_at)
            > requirement.max_age_seconds()
    {
        anyhow::bail!("protected content availability receipt is outside its freshness window");
    }
    crate::crypto::verify_signed_json_envelope_against_dids(
        &receipt_json,
        CONTENT_AVAILABILITY_RECEIPT_DOMAIN,
        std::slice::from_ref(&requirement.expected_provider_did().to_string()),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability receipt signature is invalid"))?;
    RuntimeVerifiedContentAvailability::new(
        content_cid,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        requirement,
        receipt.payload.replicas,
        receipt.payload.checked_at,
        Digest32::new(sha2::Sha256::digest(&receipt_json).into()),
        media_identity.encrypted_content().clone(),
        media_identity.media_manifest_root(),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))
}

#[derive(Clone)]
pub(crate) struct RuntimeCustodyLibraryPublishInput {
    pub object_uri: String,
    pub principal_id: String,
    pub mime_type: String,
    pub codecs: String,
    pub wallet_account_id: String,
    pub wallet_account_address: String,
    pub creator_mint_source_digest: Digest32,
    pub copies: String,
    pub price: String,
    pub clear_init_segment: Vec<u8>,
    pub clear_segments: Vec<Vec<u8>>,
    pub source_storage: String,
}

impl std::fmt::Debug for RuntimeCustodyLibraryPublishInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyLibraryPublishInput")
            .field("object_uri", &self.object_uri)
            .field("principal_id", &self.principal_id)
            .field("mime_type", &self.mime_type)
            .field("codecs", &self.codecs)
            .field("wallet_account_id", &"[redacted]")
            .field("wallet_account_address", &"[redacted]")
            .field(
                "creator_mint_source_digest",
                &self.creator_mint_source_digest,
            )
            .field("copies", &self.copies)
            .field("price", &self.price)
            .field("clear_init_segment_bytes", &self.clear_init_segment.len())
            .field("clear_segment_count", &self.clear_segments.len())
            .field("source_storage", &self.source_storage)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeCustodyLibraryPublishFacts {
    pub content_cid: String,
    pub mint_id: Digest32,
    pub content_id: String,
    pub display_name: String,
    pub availability: Value,
    pub receipt: Value,
    pub content_security: Value,
    pub listing_uri: Option<String>,
}

fn runtime_custody_library_publish_facts(
    input: &RuntimeCustodyLibraryPublishInput,
    draft: &RuntimeMintDraft,
    content_id: &str,
    evidence: &RuntimeVerifiedContentAvailability,
) -> RuntimeCustodyLibraryPublishFacts {
    let mint_id_hex = hex::encode(draft.mint_id().as_bytes());
    let receipt_digest_hex = hex::encode(evidence.receipt_digest().as_bytes());
    let availability = json!({
        "schema": "elastos.library.runtime-custody-availability/v1",
        "cid": evidence.content_cid(),
        "content_id": content_id,
        "mint_id": mint_id_hex,
        "status": PROTECTED_CONTENT_AVAILABLE_STATUS,
        "replicas": evidence.observed_replicas(),
        "checked_at": evidence.checked_at(),
        "receipt_digest": receipt_digest_hex,
    });
    RuntimeCustodyLibraryPublishFacts {
        content_cid: evidence.content_cid().to_string(),
        mint_id: draft.mint_id(),
        content_id: content_id.to_string(),
        display_name: runtime_custody_display_name(&input.object_uri),
        availability: availability.clone(),
        receipt: json!({
            "schema": "elastos.library.runtime-custody-receipt/v1",
            "receipt_digest": receipt_digest_hex,
        }),
        content_security: json!({
            "schema": "elastos.library.published-content-security/v1",
            "object_uri": input.object_uri,
            "source_storage": input.source_storage,
            "published_payload": "runtime_custody_encrypted",
            "key_release_required": false,
            "status": "runtime_custody_available",
            "content_id": content_id,
            "mint_id": mint_id_hex,
            "required_providers": [],
        }),
        listing_uri: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuntimeCustodyListingOrigin {
    LocalCreator {
        principal_id: String,
        listing_uri: String,
        package_sha256: String,
    },
    Imported {
        listing_uri: String,
        package_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyPurchaseAccessEvidenceRecord {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) wallet: String,
    pub(crate) content_access_id: String,
    pub(crate) has_access: bool,
    pub(crate) finalized_block_number: u64,
    pub(crate) finalized_block_hash: String,
    pub(crate) finalized_block_timestamp: u64,
    pub(crate) observed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuntimeCustodyPurchaseProgress {
    Pending {
        #[serde(skip_serializing_if = "Option::is_none")]
        confirmed_buy: Option<RuntimeCustodyConfirmedPurchaseStage>,
    },
    Complete {
        terminal: RuntimeCustodyTerminalPurchaseRecord,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyPurchaseRecord {
    pub(crate) schema: String,
    pub(crate) principal_id: String,
    pub(crate) profile_did: String,
    pub(crate) mint_id: String,
    pub(crate) content_id: String,
    pub(crate) cid: String,
    pub(crate) listing_sha256: String,
    pub(crate) seller_address: String,
    pub(crate) chain_namespace: String,
    pub(crate) network: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) operative: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payment_processor: Option<String>,
    pub(crate) availability_receipt_digest: String,
    pub(crate) account_id: String,
    pub(crate) address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) approval_stage: Option<RuntimeCustodyPurchaseStageRecord>,
    pub(crate) buy_stage: RuntimeCustodyPurchaseStageRecord,
    pub(crate) progress: RuntimeCustodyPurchaseProgress,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

fn runtime_custody_display_name(object_uri: &str) -> String {
    let raw = object_uri
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("protected-content");
    let cleaned = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        return "protected-content".to_string();
    }
    truncate_utf8_to_bytes(&cleaned, MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES)
}

pub(crate) fn load_runtime_custody_purchase(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> anyhow::Result<Option<RuntimeCustodyPurchaseRecord>> {
    let path = runtime_purchase_path(data_dir, principal_id, mint_id);
    if !path.exists() {
        return Ok(None);
    }
    let record: RuntimeCustodyPurchaseRecord = serde_json::from_slice(&fs::read(path)?)?;
    if record.schema != RUNTIME_PURCHASE_SCHEMA_V1 || record.principal_id != principal_id {
        anyhow::bail!("Runtime custody purchase is invalid");
    }
    Ok(Some(record))
}

pub(crate) fn persist_runtime_custody_purchase(
    data_dir: &Path,
    purchase: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<()> {
    write_owner_only_bytes(
        &runtime_purchase_path(
            data_dir,
            &purchase.principal_id,
            parse_mint_id_hex(&purchase.mint_id)?,
        ),
        &serde_json::to_vec(purchase)?,
    )
}

fn parse_mint_id_hex(value: &str) -> anyhow::Result<Digest32> {
    let bytes = decode_hex_bytes(value)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint identity is invalid"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Runtime custody mint identity is invalid"))?;
    Ok(Digest32::new(bytes))
}

pub(crate) fn load_runtime_custody_profile_did(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<String> {
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let profile = crate::collaboration_profile_authority::load_profile_authority(
        data_dir,
        principal_id,
        &localhost_root,
    )?
    .ok_or_else(release_unavailable_missing!())?;
    Ok(profile.document().profile_did.clone())
}

fn runtime_purchase_path(data_dir: &Path, principal_id: &str, mint_id: Digest32) -> PathBuf {
    let mut hasher = sha2::Sha256::new();
    hasher.update(principal_id.as_bytes());
    data_dir
        .join(RUNTIME_PURCHASE_ROOT)
        .join(hex::encode(hasher.finalize()))
        .join(format!("{}.json", hex::encode(mint_id.as_bytes())))
}

fn runtime_storage_write_error(reason: String) -> anyhow::Error {
    anyhow::anyhow!("Runtime custody protected-content storage is unavailable: {reason}")
}

#[cfg(unix)]
fn ensure_owner_only_runtime_storage_parent(path: &Path) -> anyhow::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        if cursor.exists() {
            let metadata = fs::symlink_metadata(cursor).map_err(|_| {
                runtime_storage_write_error("parent path is unavailable".to_string())
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!(
                    "{}",
                    runtime_storage_write_error(
                        "parent path must be an owner-only directory".to_string()
                    )
                );
            }
            validate_owner_only_metadata_with_error(
                "protected-content runtime storage parent",
                &metadata,
                false,
                runtime_storage_write_error,
            )?;
            break;
        }
        missing.push(cursor.to_path_buf());
        cursor = cursor
            .parent()
            .ok_or_else(|| runtime_storage_write_error("parent path is unavailable".to_string()))?;
    }
    for dir in missing.iter().rev() {
        fs::create_dir(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    for dir in missing {
        let metadata = fs::symlink_metadata(&dir)
            .map_err(|_| runtime_storage_write_error("parent path is unavailable".to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!(
                "{}",
                runtime_storage_write_error(
                    "parent path must be an owner-only directory".to_string()
                )
            );
        }
        validate_owner_only_metadata_with_error(
            "protected-content runtime storage parent",
            &metadata,
            false,
            runtime_storage_write_error,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_runtime_storage_parent(parent: &Path) -> anyhow::Result<()> {
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn runtime_storage_temp_path(path: &Path) -> anyhow::Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| runtime_storage_write_error("parent path is unavailable".to_string()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| runtime_storage_write_error("storage path is invalid".to_string()))?;
    for _ in 0..16 {
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let candidate = parent.join(format!(
            ".{}.tmp-{}",
            file_name.to_string_lossy(),
            hex::encode(nonce)
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "{}",
        runtime_storage_write_error("temporary path allocation failed".to_string())
    );
}

fn write_owner_only_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        ensure_owner_only_runtime_storage_parent(parent)?;
        #[cfg(not(unix))]
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        let temp_path = runtime_storage_temp_path(path)?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true).mode(0o600);
        let mut file = options.open(&temp_path)?;
        let result = (|| -> anyhow::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, path)?;
            if let Some(parent) = path.parent() {
                sync_runtime_storage_parent(parent)?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result?;
    }
    #[cfg(not(unix))]
    {
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, bytes)?;
        fs::rename(temp_path, path)?;
    }
    Ok(())
}
