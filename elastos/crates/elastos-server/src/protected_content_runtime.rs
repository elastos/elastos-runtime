//! Protected-content Runtime provider plane.
//!
//! This module registers the Runtime-owned `protect`, `media`, `custody`, and
//! `protected-content-decrypt` targets, scans the durable Runtime release
//! journal on startup, and evaluates policy through the `chain` registry
//! route. Library mint, buy, open, read, and close use these seams. It is the
//! only protected-content authority, and it exposes no provider topology to
//! capsules.

#[cfg(test)]
mod pool_mint_tests;
pub mod remote_dash_source;
#[cfg(test)]
pub(crate) mod tests;
mod unfinished_mint;

pub(crate) use unfinished_mint::*;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};

use crate::custody_release_limits::{
    CustodyReleaseLimiter, RuntimeInvocationSource, CUSTODY_NODE_SETTINGS, RATE_LIMITED_CODE,
};
use crate::custody_surface::{
    carrier_op_allowed, declared_ops, runtime_local_op_allowed, OP_CUSTODY_EVALUATE,
    OP_CUSTODY_PROVISION_NODE_SHARE, OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
    OP_CUSTODY_RELEASE_CONTRIBUTION, OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
    OP_CUSTODY_SIGN_POOL_STATEMENT, OP_CUSTODY_STATUS, TARGET_CUSTODY,
};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::{
    validate_custody_epoch_against_pool_at, CanonicalContract, ContentAccessIdV1,
    CustodyCommitteeAuthorizationIdentityV1, CustodyEnvelopeV1, CustodyEpochIssuerKeyV1, Digest32,
    EncryptedContentIdentityV1, KeyReleaseOutcomeV1, KeyReleaseRequestV1, NodeContributionRefV1,
    NodeCustodyPublicKeyV1, NodePublicKey, ProfileIdentityV1, RecipientKeyAuthorizationStatementV1,
    RecipientKeyIdentityV1, RecipientPublicKeyBytesV1, ReplayNonce16, RightsActionV1,
    RightsEvaluationEvidenceRequestV1, RightsPolicyBodyV1, RightsPolicyIdentityV1,
    RightsRequestAnyV1, RightsRequestV1, RightsRequestV2, RuntimeOperationIssuerKeyV1,
    RuntimeReleaseAuditIdV1, RuntimeReleaseOperationAnyV1, RuntimeReleaseOperationStatementV1,
    RuntimeSessionBindingV1, SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1,
    SignedCustodyPoolV1, SignedPoolDescriptorAnyV1, SignedRuntimeReleaseOperationV1,
    SignedTerminalReceiptV1, TerminalReceiptIssuerKey, TerminalReceiptStatementV1,
    ViewerPartIndexV1, WalletAddress, WalletSignedRightsRequestAnyV1, WalletSignedRightsRequestV1,
};
use elastos_protected_content_provider_contracts::{
    build_cenc_dash_mpd_v2, cenc_dash_merkle_audit_path, cenc_dash_merkle_audit_paths,
    cenc_dash_merkle_root, cenc_dash_segment_leaf_hash, pinned_declaration_v2,
    CencDashIdentityBuilderV2, CencDashMediaIdentityV2, CencDashMpdRenditionV2,
    CencDashMpdSegmentV2, CencDashRenditionDeclV2, CencDashRenditionKindV2,
    CencFmp4MediaIdentityV1, CencLayoutProfile, CencMediaSuite, ChunkedPayloadObjectIdentityV1,
    CustodyProtectionHeader, DecryptProviderRequestOpV1, DecryptProviderRequestV1,
    DecryptProviderResponseV1, Fmp4SegmentTimelineV2, ProtectFailureReasonV2,
    ProtectProviderRequestV1, ProtectProviderResponseStatusV1, ProtectProviderResponseV1,
    ProtectionRepresentationV2, ProtectionSessionNodeV1, RightsProviderRequestV1,
    RightsProviderResponseV1, ValidatedCencDashRenditionSessionV2,
    ValidatedClearFmp4MediaSessionLayoutV1, ViewerMediaPartSelectorV1,
    ATTEST_REMOTE_SEAL_UPLOAD_OP, AUTHORIZE_REMOTE_SEAL_SHARE_OP,
    CUSTODY_PROVIDER_REQUEST_SCHEMA_V1, CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1, DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
    MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1, MAX_PROTECT_MEDIA_PART_BYTES_V1,
    MAX_PROTECT_MEDIA_SEGMENTS_V1, MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1,
    MAX_VIEWER_MEDIA_PART_BYTES_V1, PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
    PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
};
use elastos_protected_content_provider_contracts::{
    ProvisionRemoteShareCommandV1, RemoteShareDeliveryV1, RemoteShareProvisionRequestV1,
    SIGN_REMOTE_SEAL_COMPLETION_OP,
};
use elastos_protected_content_rights::{
    PrivateCustodyRightsRequestV1, CHAIN_PROVIDER_ID, CHAIN_RIGHTS_EVIDENCE_OP,
};
use elastos_protected_content_runtime::RuntimeProviderCallError;
use elastos_protected_content_runtime::{
    cancel_prepared_recipient, cancel_prepared_recipient_with_result_by_handle,
    close_viewer_session_with_result, open_viewer_session, prepare_recipient,
    read_viewer_media_part, read_viewer_object_chunk, resolve_runtime_mint_selected_nodes,
    ExclusiveFileLock, PersistedRuntimeMint, PersistedRuntimeReleaseOperation,
    RuntimeContentAvailabilityRequirement, RuntimeContentIdentityV1, RuntimeCustodyTerminalKind,
    RuntimeDecryptProvider, RuntimeMediaPreparationRecord, RuntimeMediaPreparationState,
    RuntimeMintConfiguredCustodyProvider, RuntimeMintCoordinator, RuntimeMintCoordinatorError,
    RuntimeMintCoordinatorOutcome, RuntimeMintCreatorStage, RuntimeMintCreatorState,
    RuntimeMintCreatorTerminalEvidence, RuntimeMintDraft, RuntimeMintIntent,
    RuntimeMintIntentRenditionV2, RuntimeMintJournal, RuntimeOpenViewerContentV1,
    RuntimeOpenViewerSessionInput, RuntimePreparedRecipient, RuntimePreparedRecipientCancelResult,
    RuntimeProtectedContentPurchaseIntent, RuntimePurchaseEffectAuthority,
    RuntimeReleaseAuditRecord, RuntimeReleaseCoordinator, RuntimeReleaseCoordinatorOutcome,
    RuntimeReleaseJournal, RuntimeReleaseJournalError, RuntimeReleaseTerminalResult,
    RuntimeSelectedProvider, RuntimeVerifiedContentAvailability,
    RuntimeVerifiedContentIdentityRootV1, RuntimeVerifiedPurchaseEffect, RuntimeViewerSession,
    RuntimeViewerSessionCloseResult,
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

/// Protected content (Creator, Custody, Elacity Player, Elacity Reader, Protect
/// and List, Marketplace Media) ships after 0.8.0 (#91). It stays off, and Home
/// hides those surfaces and refuses protected publishing, unless the host sets
/// `elastos config set protected_content true`.
pub(crate) fn protected_content_enabled(data_dir: &Path) -> bool {
    protected_content_enabled_in(read_home_config(data_dir).as_ref())
}

/// `protected_content` in a config snapshot; off when absent.
pub(crate) fn protected_content_enabled_in(config: Option<&toml::Table>) -> bool {
    config
        .and_then(|config| config.get("protected_content"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

pub(crate) const PROTECT_PROVIDER_ID: &str = "protect";
pub(crate) const MEDIA_PROVIDER_ID: &str = "media";
pub(crate) const RUNTIME_PROVIDER_ID: &str = "runtime";
pub(crate) const PROTECTED_CONTENT_DECRYPT_PROVIDER_ID: &str = "protected-content-decrypt";
const CONTENT_PROVIDER_ID: &str = "content";
pub(crate) const PROTECTED_CONTENT_REPLICATION_POLICY: &str = "protected-content-replication/v1";
const _: () =
    assert!(PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR <= PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET);
pub(crate) const PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS: u64 = 60;
pub(crate) const PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS: u64 = 5;

pub(crate) const RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE: &str =
    "Runtime custody composition is not configured";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE: &str =
    "Runtime custody purchase is pending exact Wallet or Chain settlement";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_UNBOUND_MESSAGE: &str =
    "Runtime custody purchase target is not bound on chain";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody purchase is unavailable";
pub(crate) const RUNTIME_CUSTODY_DOWNLOAD_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody download is unavailable";

/// Plan B T4.6: the item's pool cannot be found or used from this Home: no
/// descriptor names its epoch (own, served or known), or the listing is an
/// imported package on a Home that does not hold its ciphertext (S4-Q14).
/// It travels as data -- `code` `custody_unresolved` -- and is final until
/// the pool is added in Custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCustodyUnresolved;

impl RuntimeCustodyUnresolved {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const CODE: &'static str = "custody_unresolved";

    pub(crate) fn error() -> anyhow::Error {
        anyhow::Error::new(Self).context(RUNTIME_CUSTODY_UNRESOLVED_MESSAGE)
    }
}

impl std::fmt::Display for RuntimeCustodyUnresolved {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("this item's pool cannot be reached from this Home")
    }
}

impl std::error::Error for RuntimeCustodyUnresolved {}

pub(crate) const RUNTIME_CUSTODY_UNRESOLVED_MESSAGE: &str =
    "This item's pool cannot be reached from this Home yet. Add the pool in Custody.";

pub(crate) const RUNTIME_CUSTODY_POOL_CONTENT_UNAVAILABLE_MESSAGE: &str =
    "This file isn't available from the pool right now. Try again later.";

/// Plan B T4.4: the item's pool resolves, but none of its nodes can serve
/// this Home now. Not resumable; the viewer offers Retry (S4-Q16).
pub(crate) const RUNTIME_CUSTODY_NO_ELIGIBLE_SERVER_MESSAGE: &str =
    "No node of this item's pool can play it now. Try again later.";

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
pub(crate) const PROTECTED_CONTENT_IDENTITY_PATH: &str = "protected-content/v1/identity.bin";
pub(crate) const PROTECTED_CONTENT_INIT_PATH: &str = "protected-content/v1/init.mp4";
const PROTECTED_CONTENT_SEGMENTS_PREFIX: &str = "protected-content/v1/segments/";
const PROTECTED_CONTENT_SEGMENTS_SUFFIX: &str = ".m4s";
const PROTECTED_CONTENT_AVAILABLE_STATUS: &str = "network_available";

const CONTENT_AVAILABILITY_RECEIPT_SCHEMA: &str = "elastos.content.availability.receipt/v1";
const CONTENT_AVAILABILITY_RECEIPT_DOMAIN: &str = "elastos.content.availability.receipt.v1";
const MEDIA_PROVIDER_PROCESS_ID: &str = "media-provider";
/// Historical directory name. The path is frozen because provisioned custody
/// hosts already hold state there; `inactive` says nothing about whether the
/// custody plane is active.
const INACTIVE_CUSTODY_ROOT: &str = "protected-content/custody-provider/inactive";
const MEDIA_PROVIDER_PREPARED_MEDIA_SCHEMA_V2: &str = "elastos.media-provider.prepared-media/v2";
/// The protocol's part rule for a prepared (clear) part: 2 MiB less 64 KiB, so
/// that protecting it, which adds at most a few KiB, stays under the 2 MiB
/// protected part and the decrypt answer stays under the provider frame. It
/// bounds one part, never a whole media: there is no cap on duration, size or
/// segment count.
const MEDIA_PROVIDER_MAX_PREPARED_PART_BYTES_V2: u64 = 2 * 1024 * 1024 - 64 * 1024;

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
        self.invoke_custody(OP_CUSTODY_RELEASE_CONTRIBUTION, request)
            .await
    }

    async fn provision_node_share(
        &self,
        request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_custody(OP_CUSTODY_PROVISION_NODE_SHARE, request)
            .await
    }

    async fn release_pool_contribution(
        &self,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_pool_custody(OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, request)
            .await
    }

    async fn provision_pool_node_share(
        &self,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_pool_custody(OP_CUSTODY_PROVISION_POOL_NODE_SHARE, request)
            .await
    }
}

pub fn runtime_release_journal(data_dir: &Path) -> RuntimeReleaseJournal {
    RuntimeReleaseJournal::new(data_dir.join("protected-content").join("runtime-release"))
}

fn runtime_mint_media_renditions(
    media: &RuntimePreparedMediaV2,
) -> Vec<RuntimeMintIntentRenditionV2> {
    media
        .renditions
        .iter()
        .map(|rendition| RuntimeMintIntentRenditionV2 {
            kind: rendition.kind,
            segment_count: rendition.segment_count,
        })
        .collect()
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

/// OPEN-LOOP F4: this Home's own custody node keys, the one answer to "is
/// this node mine": the key every root on disk holds, so the served pools'
/// nodes and the node Include set up alike. A root whose key cannot be read
/// runs no node and is left out.
pub(crate) fn own_custody_node_keys(data_dir: &Path) -> anyhow::Result<Vec<NodePublicKey>> {
    Ok(custody_provider_root_paths(data_dir)?
        .iter()
        .filter_map(|root| {
            custody_provider::load_node_public_key(&custody_root_dir(data_dir, root)).ok()
        })
        .collect())
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

/// The Runtime operation issuer this host's Chain plane checks release
/// operations against. A custody node settles releases for the one Runtime
/// its custody state was provisioned to trust, never for this host's own
/// device key; a host without custody state is its own Runtime.
pub fn chain_plane_runtime_issuer(data_dir: &Path) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
    let custody_state_root = inactive_custody_state_root(data_dir);
    if custody_state_root.is_dir() {
        return custody_provider::load_trusted_runtime_issuer(&custody_state_root).map_err(
            |error| {
                anyhow::anyhow!(
                    "provisioned custody state names no readable trusted Runtime issuer: {error:?}"
                )
            },
        );
    }
    let device_key = elastos_identity::load_or_create_device_key(data_dir)
        .map_err(|_| anyhow::anyhow!("chain-provider host identity is unavailable"))?;
    derive_protected_content_runtime_issuer(&device_key)
}

pub(crate) fn protected_content_root(data_dir: &Path) -> PathBuf {
    data_dir.join(PROTECTED_CONTENT_ROOT)
}

pub(crate) fn validate_owner_only_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let _ = error;
        invalid_custody_config(format!("{label} is unavailable"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "{}",
            invalid_custody_config(format!("{label} must be an owner-only directory"))
        );
    }
    validate_owner_only_metadata_with_error(label, &metadata, false, invalid_custody_config)
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

/// The pool a mint goes into (Plan B POOL-MINT): this Home's own
/// composition, or the committee of a pool it uses, with that pool's
/// descriptor.
pub(crate) struct RuntimeCustodyMintPool {
    pub(crate) composition: RuntimeCustodyComposition,
    pub(crate) used: Option<SignedPoolDescriptorAnyV1>,
    /// PM-F5: the pool and epoch a recorded mint already uses. Settling it
    /// skips the freshness checks only new provisioning needs.
    pub(crate) recorded: bool,
    completed_local_mint: Option<Digest32>,
}

impl RuntimeCustodyMintPool {
    /// The committee's nodes for this mint: the provisioning rule for a new
    /// mint, the release rule (no pool term) for a recorded one (PM-F5).
    pub(crate) fn selected_nodes<'a>(
        &self,
        configured: &'a [elastos_protected_content_runtime::RuntimeMintConfiguredCustodyProvider<
            'a,
        >],
        now: u64,
    ) -> anyhow::Result<Vec<elastos_protected_content_runtime::RuntimeMintSelectedNode<'a>>> {
        let composition = &self.composition;
        let resolve = if self.recorded {
            elastos_protected_content_runtime::resolve_recorded_runtime_mint_selected_nodes
        } else {
            resolve_runtime_mint_selected_nodes
        };
        resolve(
            composition.expected_policy_authority,
            composition.expected_authorization_identity,
            &composition.signed_pool,
            &composition.signed_epoch,
            &composition.signed_committee_authorization,
            now,
            configured,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody mint selection is invalid"))
    }
}

const MAX_RUNTIME_POOL_MINT_FILE_BYTES: usize = 128 * 1024;

fn runtime_pool_mints_dir(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(RUNTIME_POOL_MINTS_DIR)
}

fn read_runtime_pool_mint_file<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> anyhow::Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let bytes = crate::collaboration_config::read_owner_only_file(
        path,
        MAX_RUNTIME_POOL_MINT_FILE_BYTES,
        "runtime pool mint",
    )?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// The source's current attempt, and whether its intent is written. `None`
/// for a Home that never minted (reading would create the journal).
fn runtime_mint_attempt_state(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<Option<(Digest32, Option<RuntimeMintIntent>)>> {
    if fs::symlink_metadata(runtime_mint_journal_root(data_dir)).is_err() {
        return Ok(None);
    }
    let journal = runtime_mint_journal(data_dir);
    let attempt = journal
        .current_attempt(principal_id, object_uri, source_storage)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let intent = match journal.load_intent(attempt.request_id()) {
        Ok(intent) => Some(intent),
        Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => None,
        Err(_) => anyhow::bail!("Runtime custody mint intent is unavailable"),
    };
    Ok(Some((attempt.request_id(), intent)))
}

/// Plan B POOL-MINT: the pool this mint goes into.
/// - A source whose intent is written keeps the pool it recorded (S7I-F1):
///   the recorded pool file, else this Home's own composition. No
///   reselection and no fallback.
/// - `requested` names a pool: this Home's own, or one it uses.
/// - Otherwise this Home's own pool, else the only pool it uses.
///
/// Refused plainly when there is none, before any media work. A new pool
/// mint is recorded for its attempt before the intent is written.
pub(crate) fn load_runtime_custody_mint_pool(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    requested: Option<&str>,
    source: Option<(&str, &str, &str)>,
) -> anyhow::Result<RuntimeCustodyMintPool> {
    let now = crate::auth::now_ts();
    let attempt = match source {
        Some((principal, uri, storage)) => {
            runtime_mint_attempt_state(data_dir, principal, uri, storage)?
        }
        None => None,
    };
    let used_pool =
        |descriptor: SignedPoolDescriptorAnyV1,
         recorded: Option<elastos_protected_content_contracts::CustodyEpochIdentityV1>|
         -> anyhow::Result<RuntimeCustodyMintPool> {
            Ok(RuntimeCustodyMintPool {
                composition: runtime_custody_composition_for_pool(
                    data_dir,
                    registry.clone(),
                    &descriptor,
                    recorded,
                    now,
                )?,
                used: Some(descriptor),
                recorded: recorded.is_some(),
                completed_local_mint: None,
            })
        };
    if let Some((request_id, Some(intent))) = &attempt {
        return match recorded_runtime_mint_pool(data_dir, *request_id)? {
            Some(descriptor) => used_pool(descriptor, Some(intent.custody_epoch())),
            None => Ok(RuntimeCustodyMintPool {
                composition: load_mint_composition_for_intent(
                    data_dir,
                    registry.clone(),
                    intent,
                    now,
                )?,
                used: None,
                recorded: intent.completed_mint_id().is_some(),
                completed_local_mint: intent.completed_mint_id(),
            }),
        };
    }
    let own = load_runtime_custody_composition_snapshot(
        data_dir,
        &runtime_custody_composition_config_path(data_dir),
        registry.clone(),
    )?;
    let own_pool = own.as_ref().map(|(own, _)| {
        elastos_protected_content_contracts::PoolDidV1::from_issuer(own.expected_policy_authority)
    });
    let mut used = runtime_custody_used_pools(data_dir, own_pool.as_ref(), now);
    let chosen = match requested {
        Some(did) => {
            let pool = elastos_protected_content_contracts::PoolDidV1::parse_did_key(did)
                .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
            if own_pool == Some(pool) {
                None
            } else {
                Some(
                    used.into_iter()
                        .find(|descriptor| descriptor.pool() == &pool)
                        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?,
                )
            }
        }
        None if own.is_some() => None,
        None => match used.len() {
            0 => anyhow::bail!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE),
            1 => Some(used.remove(0)),
            _ => anyhow::bail!(RUNTIME_CUSTODY_MINT_POOL_CHOICE_MESSAGE),
        },
    };
    let pool = match chosen {
        None => {
            let (composition, bytes) =
                own.ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
            if source.is_some() {
                retain_mint_composition(
                    data_dir,
                    composition.expected_authorization_identity,
                    &bytes,
                )?;
            }
            RuntimeCustodyMintPool {
                composition,
                used: None,
                recorded: false,
                completed_local_mint: None,
            }
        }
        Some(descriptor) => used_pool(descriptor, None)?,
    };
    // A used pool is recorded for the attempt. A composition mint needs no
    // record; it only overwrites one an earlier choice for this attempt left.
    let recorded_before = match (&attempt, &pool.used) {
        (Some((request_id, _)), None) => {
            fs::symlink_metadata(runtime_pool_mint_attempt_path(data_dir, *request_id)).is_ok()
        }
        _ => false,
    };
    if let Some(source) = source {
        if pool.used.is_some() || recorded_before {
            record_runtime_mint_attempt_pool(data_dir, source, pool.used.as_ref())?;
        }
    }
    Ok(pool)
}

/// Writes the pool mint record once; a record already there is kept.
fn record_runtime_pool_mint(
    data_dir: &Path,
    draft: &RuntimeMintDraft,
    descriptor: &SignedPoolDescriptorAnyV1,
    device_key: &elastos_runtime::signature::SigningKey,
) -> anyhow::Result<()> {
    if runtime_pool_mint_record(data_dir, draft.mint_id())?.is_some() {
        return Ok(());
    }
    let issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let sign_key = device_key.clone();
    let mint_share = elastos_protected_content_runtime::sign_pool_mint_share(
        descriptor,
        draft.key_envelope(),
        draft.content_access_id(),
        issuer,
        &move |bytes: &[u8]| sign_key.sign(bytes).to_bytes(),
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody pool mint share is invalid"))?;
    write_runtime_pool_mint_file(
        data_dir,
        &runtime_pool_mint_path(data_dir, draft.mint_id()),
        &RuntimePoolMintRecordV2 {
            schema: RUNTIME_POOL_MINT_SHARE_SCHEMA_V1.to_string(),
            mint_share_base64: base64::engine::general_purpose::STANDARD
                .encode(mint_share.canonical_bytes()?),
        },
    )?;
    tracing::debug!(
        mint_id = %hex::encode(draft.mint_id().as_bytes()),
        "runtime custody publish: pool mint recorded"
    );
    Ok(())
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

/// Why a provider invocation did not yield data, keeping the distinction the
/// formatted-string form throws away.
///
/// The distinction that matters to a caller holding a durable journal is
/// whether the provider can have acted. `NotCompleted` is the only variant that
/// says nothing either way: the registry call failed, which covers a provider
/// that was never reached *and* a reply that was lost after the provider did
/// its work. `Refused` carries the provider's own code, which is the sole
/// evidence a caller has for classifying the refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProviderInvocationFailure {
    /// The registry call itself failed. The request may or may not have reached
    /// the provider, and a reply may have been lost on the way back.
    NotCompleted { detail: String },
    /// The provider answered `status: "error"` with its own code and message.
    Refused { code: String, message: String },
    /// The provider answered, but the frame was not a usable response.
    MalformedResponse { detail: String },
}

impl ProviderInvocationFailure {
    /// The formatted form the string-returning callers have always seen. Kept
    /// byte-identical so widening the typed layer changes no existing message.
    fn into_message(self, target: &str, op: &str) -> String {
        match self {
            Self::NotCompleted { detail } => {
                format!("{target} provider {op} invocation failed: {detail}")
            }
            Self::Refused { code, message } => {
                format!("{target} provider {op} rejected the request: {code}: {message}")
            }
            Self::MalformedResponse { detail } => detail,
        }
    }
}

pub(crate) async fn invoke_json_provider_with_transport(
    registry: &ProviderRegistry,
    target: &str,
    op: &str,
    request: Value,
    transport: ProviderInvocationTransport,
) -> Result<Value, String> {
    invoke_json_provider_classified(registry, target, op, request, transport)
        .await
        .map_err(|failure| failure.into_message(target, op))
}

/// The same invocation, with the failure kept as data.
pub(crate) async fn invoke_json_provider_classified(
    registry: &ProviderRegistry,
    target: &str,
    op: &str,
    request: Value,
    transport: ProviderInvocationTransport,
) -> Result<Value, ProviderInvocationFailure> {
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
            ProviderInvocationFailure::NotCompleted {
                detail: error.to_string(),
            }
        })?;
    let Some(status) = response.get("status").and_then(Value::as_str) else {
        return Err(ProviderInvocationFailure::MalformedResponse {
            detail: format!("{target} provider {op} response is missing status"),
        });
    };
    match status {
        "ok" => response.get("data").cloned().ok_or_else(|| {
            ProviderInvocationFailure::MalformedResponse {
                detail: format!("{target} provider {op} response is missing data"),
            }
        }),
        "error" => {
            // Keep the provider's own code/message: this travels back to the
            // caller (over Carrier for a committee member) and is the only
            // trace of why a node refused.
            let code = response
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let message = response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            tracing::warn!(%target, %op, %code, %message, "provider rejected the request");
            Err(ProviderInvocationFailure::Refused {
                code: code.to_string(),
                message: message.to_string(),
            })
        }
        _ => Err(ProviderInvocationFailure::MalformedResponse {
            detail: format!("{target} provider {op} response has unsupported status"),
        }),
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
        || requirement.minimum_replicas() < PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR
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
                    "require_live_multi_peer_proof":
                        protected_content_live_proof_required(requirement.minimum_replicas()),
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
            PROTECTED_CONTENT_IDENTITY_PATH
            | PROTECTED_CONTENT_INIT_PATH
            | PROTECTED_CONTENT_OBJECT_EPC1_PATH
            | PROTECTED_CONTENT_OBJECT_MANIFEST_PATH => {}
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

pub(crate) fn protected_content_segment_path(index: usize) -> String {
    format!("{PROTECTED_CONTENT_SEGMENTS_PREFIX}{index:08}{PROTECTED_CONTENT_SEGMENTS_SUFFIX}")
}

async fn verify_protected_content_manifest_and_files(
    registry: &ProviderRegistry,
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    media_identity: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let expected_files = protected_content_media_manifest_files(manifest, media_identity)?;
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
    publisher_binding: RuntimeManifestPublisherBinding,
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
        || !protected_content_availability_status_accepted(&receipt.payload.status, requirement)
        || receipt.payload.replicas < requirement.minimum_replicas()
        || (protected_content_live_proof_required(requirement.minimum_replicas())
            && receipt
                .payload
                .peer_selection
                .get("live_multi_peer_proof")
                .and_then(Value::as_bool)
                != Some(true))
        || manifest.object_did.as_deref() != Some(requirement.expected_object_identity())
        || !content_manifest_binds_publisher(manifest, requirement, publisher_binding)
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
        RuntimeVerifiedContentIdentityRootV1::for_media(media_identity),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))
}

async fn verify_protected_content_object_manifest_and_files(
    registry: &ProviderRegistry,
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<()> {
    let expected_files = protected_content_object_manifest_files(manifest, object_identity)?;
    for file in &expected_files {
        let bytes =
            crate::content::fetch_bytes_via_provider(registry, content_cid, Some(&file.path))
                .await?;
        crate::content::verify_content_object_file(content_cid, file, &bytes)?;
        if file.path == PROTECTED_CONTENT_OBJECT_MANIFEST_PATH
            && bytes != protected_content_object_manifest_bytes(object_identity)?
        {
            anyhow::bail!("protected content descriptor is invalid");
        }
    }
    Ok(())
}

/// Object twin of `read_runtime_media_source`'s read (not its media-specific
/// stored-length preflight, which does not apply to a plain uploaded file):
/// reads the principal-scoped object and refuses only an empty one. Minting
/// applies no size bound; the read itself is `auth.rs`'s (#444).
pub(crate) fn read_runtime_object_source(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_file_path: &Path,
) -> anyhow::Result<Vec<u8>> {
    const MESSAGE: &str = "Runtime custody object publish input is invalid";
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let bytes = crate::auth::read_principal_root_object(
        data_dir,
        principal_id,
        &localhost_root,
        object_uri,
        source_file_path,
    )
    .map_err(|error| {
        tracing::warn!(
            %object_uri,
            error = ?error,
            "runtime custody object publish: source object is unreadable"
        );
        error.context(MESSAGE)
    })?;
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("source plaintext is empty").context(MESSAGE));
    }
    Ok(bytes)
}

fn invalid_prepared_media_output() -> anyhow::Error {
    anyhow::anyhow!("Runtime custody media preparation output is invalid")
}

/// One clear media part: `prepared/<rendition>/segments/NNNNNNNN.m4s`.
fn runtime_prepared_segment_path(
    operation_root: &Path,
    kind: CencDashRenditionKindV2,
    index: u32,
) -> PathBuf {
    runtime_prepared_rendition_dir(operation_root, kind)
        .join(MEDIA_PROVIDER_SEGMENTS_DIR_NAME)
        .join(format!("{index:08}.m4s"))
}

/// The preparation receipt, fed one part at a time so it never needs the media
/// in memory: `SHA-256(domain || u8 n || per rendition: u8 kind || mime || 0 ||
/// codecs || 0 || u64 init_len || sha256(init) || u64 segment_count || per
/// segment: u64 index || u64 len || sha256(segment))`.
struct RuntimeMediaPreparationReceiptV2(sha2::Sha256);

impl RuntimeMediaPreparationReceiptV2 {
    fn new(rendition_count: usize) -> anyhow::Result<Self> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(RUNTIME_MEDIA_PREPARATION_RECEIPT_DOMAIN);
        hasher
            .update([u8::try_from(rendition_count).map_err(|_| invalid_prepared_media_output())?]);
        Ok(Self(hasher))
    }

    fn begin_rendition(
        &mut self,
        kind: CencDashRenditionKindV2,
        clear_init_segment: &[u8],
        segment_count: u32,
    ) {
        let (mime_type, codecs) = pinned_declaration_v2(kind);
        self.0.update([kind.code()]);
        self.0.update(mime_type.as_bytes());
        self.0.update([0]);
        self.0.update(codecs.as_bytes());
        self.0.update([0]);
        self.0
            .update((clear_init_segment.len() as u64).to_be_bytes());
        self.0.update(sha2::Sha256::digest(clear_init_segment));
        self.0.update(u64::from(segment_count).to_be_bytes());
    }

    fn push_segment(&mut self, index: u32, segment: &[u8]) -> Digest32 {
        let digest = Digest32::new(sha2::Sha256::digest(segment).into());
        self.0.update(u64::from(index).to_be_bytes());
        self.0.update((segment.len() as u64).to_be_bytes());
        self.0.update(digest.as_bytes());
        digest
    }

    fn finish(self) -> Digest32 {
        Digest32::new(self.0.finalize().into())
    }
}

/// What the media provider reports it prepared.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePreparedMediaProviderOutputV2 {
    schema: String,
    renditions: Vec<RuntimePreparedMediaProviderRenditionV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePreparedMediaProviderRenditionV2 {
    rendition: String,
    mime_type: String,
    codecs: String,
    segment_count: u32,
}

impl RuntimePreparedMediaProviderOutputV2 {
    /// The renditions it declares as `(kind, segment count)`: the v2 schema,
    /// one or two renditions with video first, and each one's pinned pair.
    fn declared_renditions(&self) -> anyhow::Result<Vec<(CencDashRenditionKindV2, u32)>> {
        if self.schema != MEDIA_PROVIDER_PREPARED_MEDIA_SCHEMA_V2 {
            return Err(refuse_prepared_media_output("the output schema is not v2"));
        }
        let mut declared = Vec::with_capacity(self.renditions.len());
        for rendition in &self.renditions {
            let kind = runtime_media_dash_rendition_kind(&rendition.rendition)
                .ok_or_else(|| refuse_prepared_media_output("an unknown rendition"))?;
            let (mime_type, codecs) = pinned_declaration_v2(kind);
            if rendition.mime_type != mime_type
                || rendition.codecs != codecs
                || rendition.segment_count == 0
                || declared.last().is_some_and(|(last, _)| *last >= kind)
            {
                return Err(refuse_prepared_media_output(
                    "a rendition is not the pinned pair, is empty, or is out of order",
                ));
            }
            declared.push((kind, rendition.segment_count));
        }
        if declared.is_empty() {
            return Err(refuse_prepared_media_output("no rendition"));
        }
        Ok(declared)
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeCustodyLibraryPublishInput {
    pub object_uri: String,
    pub principal_id: String,
    pub wallet_account_id: String,
    pub wallet_account_address: String,
    pub creator_mint_source_digest: Digest32,
    pub copies: String,
    /// What a buyer pays for one copy, as a decimal amount of the pay token --
    /// scaled to its base units where the token's decimals are known, which is
    /// not here.
    pub price: String,
    /// The channel this mint publishes into. Never empty: a publish that named
    /// none was refused at the library boundary.
    pub channel: String,
    /// The token the sale is priced in. Empty means the mint source's first
    /// offered token.
    pub pay_token: String,

    /// The validated clear media, which the mint streams from disk one part at
    /// a time.
    pub media: RuntimePreparedMediaV2,
    pub source_storage: String,
    pub listing: Option<crate::library::RuntimeCustodyListingTerms>,
    /// Plan B S7-lite T7.6: the pool this mint goes into; `None` is this
    /// Home's own pool, else the only pool that admits it.
    pub pool_did: Option<String>,
}

impl std::fmt::Debug for RuntimeCustodyLibraryPublishInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyLibraryPublishInput")
            .field("object_uri", &self.object_uri)
            .field("principal_id", &self.principal_id)
            .field("wallet_account_id", &"[redacted]")
            .field("wallet_account_address", &"[redacted]")
            .field(
                "creator_mint_source_digest",
                &self.creator_mint_source_digest,
            )
            .field("copies", &self.copies)
            .field("price", &self.price)
            .field("media", &self.media)
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
    /// Where the `.ddrm` for this mint was filed. `None` until the tail has
    /// reached its terminal, since a capsule names a `tokenId` that does not
    /// exist before then.
    pub capsule_uri: Option<String>,
}

/// STAB-33: a pool node refused this mint's key share because its host is out
/// of storage, or has no storage maximum set. Creator names the pool and the
/// host-storage action instead of only "Runtime custody mint failed", and
/// offers the same publish again once that host has room.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyMintPoolNodeRefused {
    code: &'static str,
    pool_did: Option<String>,
}

impl RuntimeCustodyMintPoolNodeRefused {
    /// The host-storage refusal the pool's nodes reported, if any.
    fn reported(
        diagnostics: &RuntimeCustodyCallDiagnostics,
        pool_did: Option<String>,
    ) -> Option<Self> {
        let recorded = diagnostics.recorded();
        [
            crate::host_trust::HOST_STORAGE_FULL,
            crate::host_trust::HOST_STORAGE_MAX_UNSET,
        ]
        .into_iter()
        .find(|code| {
            recorded
                .iter()
                .any(|line| line.split(": ").any(|part| part.trim() == *code))
        })
        .map(|code| Self { code, pool_did })
    }

    pub(crate) fn as_json(&self) -> Value {
        json!({
            "code": self.code,
            "pool_did": self.pool_did,
            "action": "host_storage",
        })
    }
}

impl std::fmt::Display for RuntimeCustodyMintPoolNodeRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let why = if self.code == crate::host_trust::HOST_STORAGE_FULL {
            "its host storage is full"
        } else {
            "its host has no storage maximum set"
        };
        write!(
            formatter,
            "Runtime custody mint failed: a node in this item's pool refused the key share because {why}"
        )
    }
}

impl std::error::Error for RuntimeCustodyMintPoolNodeRefused {}

/// The error an aborted custody fan-out answers with: typed when a pool node
/// refused for its host storage (STAB-33), else the plain failure.
pub(crate) fn runtime_custody_mint_failed(
    diagnostics: &RuntimeCustodyCallDiagnostics,
    pool_did: Option<String>,
) -> anyhow::Error {
    match RuntimeCustodyMintPoolNodeRefused::reported(diagnostics, pool_did) {
        Some(refused) => anyhow::Error::new(refused),
        None => anyhow::anyhow!("Runtime custody mint failed"),
    }
}

/// The pool a composition mints into, as Creator names it.
fn runtime_custody_composition_pool_did(composition: &RuntimeCustodyComposition) -> Option<String> {
    elastos_protected_content_contracts::PoolDidV1::from_issuer(
        composition.expected_policy_authority,
    )
    .to_did_key()
    .ok()
}

fn remote_sealing_enabled(
    data_dir: &Path,
    existing: Option<&RuntimeMintIntent>,
    setting: &str,
) -> bool {
    existing.is_none_or(|intent| !intent.provider_effect_started())
        && read_home_config(data_dir)
            .as_ref()
            .and_then(|config| config.get(setting))
            .and_then(toml::Value::as_bool)
            == Some(true)
}

fn bind_remote_sealing_pool(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    source: (&str, &str, &str),
    mint_pool: &mut RuntimeCustodyMintPool,
    now: u64,
) -> anyhow::Result<()> {
    if mint_pool.used.is_none() {
        let descriptor = crate::custody_pool_descriptor::owner_descriptor(data_dir, now)?
            .map(SignedPoolDescriptorAnyV1::from)
            .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
        let epoch = mint_pool.composition.signed_epoch.epoch_identity()?;
        mint_pool.composition = runtime_custody_composition_for_pool(
            data_dir,
            Arc::clone(registry),
            &descriptor,
            Some(epoch),
            now,
        )?;
        record_runtime_mint_attempt_pool(data_dir, source, Some(&descriptor))?;
        mint_pool.used = Some(descriptor);
    }
    Ok(())
}

async fn finish_runtime_custody_remote_mint<
    S: elastos_protected_content_runtime::RemoteSealPartSource,
>(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    journal: &RuntimeMintJournal,
    intent: &RuntimeMintIntent,
    source: impl FnOnce() -> anyhow::Result<S>,
) -> anyhow::Result<PersistedRuntimeMint> {
    use elastos_protected_content_runtime::{
        upload_remote_seal, verify_recorded_remote_seal_attestation, PoolRemoteSealTransport,
    };

    let remote = intent
        .remote_seal_request()
        .ok_or_else(|| anyhow::anyhow!("remote seal request is unavailable"))?;
    let (device_key, device_did) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())?;
    anyhow::ensure!(
        remote.request().statement().minter_issuer == issuer,
        "remote seal request belongs to a different minter"
    );
    let request_id = intent.request_id();
    let finish = |record: PersistedRuntimeMint| {
        record_runtime_pool_mint(data_dir, record.draft(), remote.descriptor(), &device_key)?;
        Ok(record)
    };
    if let Some(record) = journal.load_adopted_remote_mint(request_id)? {
        return finish(record);
    }
    let source = source()?;
    let transport = PoolRemoteSealTransport(
        crate::custody_pool_resolver::RegistryPoolSessionTransport::new(data_dir, registry.clone()),
    );
    let completion = upload_remote_seal(
        &transport,
        &source,
        journal,
        request_id,
        issuer,
        &crate::auth::now_ts,
    )
    .await?;
    let output = verify_recorded_remote_seal_attestation(
        &completion,
        remote.descriptor(),
        remote.request(),
        remote.sealer(),
    )?;
    let statement = output.statement();
    let requirement = RuntimeContentAvailabilityRequirement::new(
        &statement.sealer_device_did,
        runtime_protected_content_id(output.identity().encrypted_content())?,
        &statement.content_publisher_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )?;
    let (requirement, availability) = verify_remote_mint_publication(
        &registry,
        &output,
        requirement,
        &device_did,
        crate::auth::now_ts,
    )
    .await?;
    let policy = resolve_runtime_rights_policy(
        &registry,
        output.identity().encrypted_content(),
        intent.content_access_id(),
        RightsActionV1::View,
    )
    .await?;
    let draft = RuntimeMintDraft::new_from_identity(
        output.identity().clone(),
        intent.content_access_id(),
        statement.key_envelope.clone(),
        policy.identity().clone(),
        statement.content_key_commitment,
        statement.key_envelope.threshold(),
        intent.nodes().to_vec(),
    )?;
    let record = journal.persist_remote_mint(request_id, &draft, &requirement, availability)?;
    finish(record)
}

fn runtime_custody_library_publish_facts(
    object_uri: &str,
    source_storage: &str,
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
        display_name: runtime_custody_display_name(object_uri),
        availability: availability.clone(),
        receipt: json!({
            "schema": "elastos.library.runtime-custody-receipt/v1",
            "receipt_digest": receipt_digest_hex,
        }),
        content_security: json!({
            "schema": "elastos.library.published-content-security/v1",
            "object_uri": object_uri,
            "source_storage": source_storage,
            "published_payload": "runtime_custody_encrypted",
            "key_release_required": false,
            "status": "runtime_custody_available",
            "content_id": content_id,
            "mint_id": mint_id_hex,
            // What the capsule protects. The Library item is a `.ddrm`, whose
            // name cannot say whether it holds a film or a PDF, so the viewer
            // routes on this rather than on the item's own extension.
            "asset_mime": draft.content_identity().content_type(),
            "required_providers": [],
        }),
        listing_uri: None,
        capsule_uri: None,
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
    /// Adopted after a market purchase from the asset's shared
    /// `metadata.json` (D10): no listing package was ever published for it,
    /// so it names the asset it was built from and its digest is computed.
    Asset {
        asset_uri: String,
        /// The immutable published package verified before local adoption.
        #[serde(skip)]
        source_listing: Option<RuntimeSourceListing>,
    },
    /// Adopted from the asset's shared `metadata.json` for a principal the
    /// chain grants access to without a purchase. It carries zero terms
    /// nobody agreed to sell on, so it is never bought, shared or listed.
    Granted { asset_uri: String },
}

impl RuntimeCustodyListingOrigin {
    /// The `elastos://` address this listing's package was published at.
    ///
    /// Both origins carry it: a local creator's listing keeps the URI it
    /// published to, and an imported one keeps the URI it was fetched from.
    /// Either way it names the same package, so passing it on is how a listing
    /// travels between Homes.
    ///
    /// An adopted listing has no package of its own; the asset it was built
    /// from is what travels instead. A granted listing travels nowhere: its
    /// terms are nobody's, so `None`.
    pub(crate) fn listing_uri(&self) -> Option<&str> {
        match self {
            Self::LocalCreator { listing_uri, .. } | Self::Imported { listing_uri, .. } => {
                Some(listing_uri)
            }
            Self::Asset {
                asset_uri,
                source_listing,
            } => Some(
                source_listing
                    .as_ref()
                    .map(|source| source.listing_uri.as_str())
                    .unwrap_or(asset_uri),
            ),
            Self::Granted { .. } => None,
        }
    }

    /// Whether this listing was built for a chain grant rather than from
    /// terms anyone offered. Such a listing is never bought, shared or listed.
    pub(crate) const fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }
}

/// The acquisition stage of a granted copy: it names the chain and nothing
/// else, because no transaction stands behind the copy.
pub(crate) fn runtime_custody_grant_stage(
    chain_namespace: &str,
    network: &str,
) -> RuntimeCustodyPurchaseStageRecord {
    RuntimeCustodyPurchaseStageRecord {
        stage: RUNTIME_CUSTODY_GRANT_STAGE.to_string(),
        effect_id: String::new(),
        approval_request_id: String::new(),
        request_sha256: String::new(),
        chain_namespace: chain_namespace.to_string(),
        network: network.to_string(),
        to: String::new(),
        value: String::new(),
        data: String::new(),
    }
}

/// `did:pkh:eip155:<chainId>:<address>` with a canonical decimal chain id and a
/// lowercase `0x` + 40 hex address, as `(chain_id, address)`.
pub(crate) fn parse_runtime_publisher_pkh(value: &str) -> Option<(u64, &str)> {
    let rest = value.strip_prefix("did:pkh:eip155:")?;
    let (chain_id, address) = rest.split_once(':')?;
    let parsed = chain_id.parse::<u64>().ok()?;
    if parsed.to_string() != chain_id {
        return None;
    }
    validate_runtime_custody_evm_address(address).ok()?;
    (address == address.to_ascii_lowercase()).then_some((parsed, address))
}

// ---------------------------------------------------------------------------
// Plan B T4.6: a Home that does not hold an item's ciphertext.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyPurchaseAccessEvidenceRecord {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) wallet: String,
    /// The KID the access was asked with (`hasAccessByContentId`). Absent on
    /// evidence asked by the item instead (R50), which names `ledger` and
    /// `token_id`. Every record written before R50 has it, and serializes
    /// exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) content_access_id: Option<String>,
    /// The item the access was asked about (`AuthorityGateway.hasAccess`,
    /// R50): set, with `token_id`, only on item-keyed evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ledger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token_id: Option<String>,
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
        /// Set once the ERC-20 approval stage's transaction has confirmed on
        /// chain, so a retried buy skips re-driving an already-confirmed
        /// approval instead of re-requesting it from the Wallet every call.
        /// Absent for two-legitimate-different reasons: native-token
        /// purchases that never had an approval stage, and records written
        /// before this field existed -- both must keep deserializing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confirmed_approval: Option<RuntimeCustodyConfirmedPurchaseStage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confirmed_buy: Option<RuntimeCustodyConfirmedPurchaseStage>,
    },
    Complete {
        terminal: RuntimeCustodyTerminalPurchaseRecord,
    },
    /// A copy the chain grants without any transaction of this principal's
    /// (acquisition `granted`). The finalized access answer is its only
    /// evidence, so it is the only state with no transaction to present; a
    /// purchase or a mint is always `Complete`.
    Granted {
        access_evidence: RuntimeCustodyPurchaseAccessEvidenceRecord,
        acquired_at: u64,
    },
}

/// Wire identity of the answer to a request to rebuild an owned copy.
pub(crate) const RUNTIME_CUSTODY_DOWNLOAD_SCHEMA_V1: &str =
    "elastos.library.runtime-custody-download/v1";

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
    /// The transaction by which this principal acquired access: the buy for a
    /// bought copy, the mint for a minted one. The open path presents it as the
    /// chain evidence behind a release, so every owned copy has one -- which is
    /// why this is not optional and why a minted copy records its mint here
    /// rather than leaving a hole or fabricating a buy.
    ///
    /// Written as `acquisition_stage`; `buy_stage` is how every record predating
    /// minted copies spells the same field.
    #[serde(alias = "buy_stage")]
    pub(crate) acquisition_stage: RuntimeCustodyPurchaseStageRecord,
    #[serde(default)]
    pub(crate) acquisition: RuntimeCustodyAcquisitionV1,
    /// Where this copy's `.ddrm` was filed in the owner's Library.
    ///
    /// `None` means no capsule has been written yet -- either the copy predates
    /// capsules, or filing one has not succeeded. That is what a repair looks
    /// for, and what keeps a replayed buy from filing a second capsule beside
    /// the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capsule_uri: Option<String>,
    pub(crate) progress: RuntimeCustodyPurchaseProgress,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

/// Which owned copy a download names.
pub(crate) enum RuntimeCustodyOwnedCopy {
    /// A copy this Home holds a listing for.
    Mint(String),
    /// A copy bought on the market, named the way the chain names it: until
    /// it is adopted there is no mint for it here to name.
    MarketItem(crate::protected_content_market::RuntimeMarketBuyItemClaim),
}

pub(crate) struct RuntimeCustodyDownloadInput {
    pub principal_id: String,
    pub copy: RuntimeCustodyOwnedCopy,
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

/// How long after an acquisition confirms its finality is still watched for.
/// Finality on Base trails the head by about 15-20 minutes. The open reads
/// finality before any Wallet request however old the copy (OPEN-LOOP OP2).
pub(crate) const RUNTIME_CUSTODY_FINALITY_WATCH_SECS: u64 = 60 * 60;

/// Opens a purchase-ledger record file for read, refusing symlinks,
/// non-regular files, and hard-linked files — the same discipline
/// `open_runtime_media_source_file` applies to media source input.
///
/// A refused file is "invalid"; a file that could not be opened or examined
/// keeps its `io::Error` in the chain (R43), so a caller can tell a record
/// that is not one from a record it could not read.
#[cfg(unix)]
pub(crate) fn open_owner_only_runtime_record_file(path: &Path) -> anyhow::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        // O_NOFOLLOW answers a symlink with ELOOP: a refusal, not a failure.
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(runtime_record_file_rejected(path))
        }
        Err(error) => return Err(runtime_record_file_unreadable(path, error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| runtime_record_file_unreadable(path, error))?;
    if !(metadata.is_file() && metadata.nlink() == 1) {
        return Err(runtime_record_file_rejected(path));
    }
    Ok(file)
}

#[cfg(not(unix))]
pub(crate) fn open_owner_only_runtime_record_file(path: &Path) -> anyhow::Result<fs::File> {
    let file = fs::File::open(path).map_err(|error| runtime_record_file_unreadable(path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| runtime_record_file_unreadable(path, error))?;
    if !metadata.is_file() {
        return Err(runtime_record_file_rejected(path));
    }
    Ok(file)
}

fn runtime_record_file_rejected(path: &Path) -> anyhow::Error {
    tracing::warn!(path = %path.display(), "purchase ledger record rejected");
    anyhow::anyhow!("Runtime custody purchase is invalid")
}

fn runtime_record_file_unreadable(path: &Path, error: std::io::Error) -> anyhow::Error {
    tracing::warn!(
        path = %path.display(),
        %error,
        "purchase ledger record could not be read"
    );
    anyhow::Error::new(error).context("Runtime custody purchase is invalid")
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
    let mut file = open_owner_only_runtime_record_file(&path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let record: RuntimeCustodyPurchaseRecord = serde_json::from_slice(&bytes)?;
    if record.schema != RUNTIME_PURCHASE_SCHEMA_V1 || record.principal_id != principal_id {
        anyhow::bail!("Runtime custody purchase is invalid");
    }
    Ok(Some(record))
}

/// This principal's listing-package purchase (`buy`) of the item the chain
/// keys `(chain_namespace, ledger, token_id)` (D2), whatever its progress --
/// the record a market purchase of the same item must not race (R29).
///
/// Purchases are filed by mint, so this reads each of the principal's
/// records. One that does not parse or validate is skipped and logged: it is
/// not a purchase this Home can stand behind, and one broken file must not
/// stop every other purchase. One that cannot be READ is an error (R43): it
/// may be a purchase under way, and the caller refuses rather than start a
/// second one beside it.
pub(crate) fn load_runtime_custody_purchase_for_chain_item(
    data_dir: &Path,
    principal_id: &str,
    chain_namespace: &str,
    ledger: &str,
    token_id: &str,
) -> anyhow::Result<Option<RuntimeCustodyPurchaseRecord>> {
    let directory = runtime_purchase_lock_path(data_dir, principal_id)
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Runtime custody purchase is invalid"))?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(mint_id) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| parse_mint_id_hex(stem).ok())
        else {
            continue;
        };
        match load_runtime_custody_purchase(data_dir, principal_id, mint_id) {
            Ok(Some(record))
                if record.chain_namespace == chain_namespace
                    && record.ledger.eq_ignore_ascii_case(ledger)
                    && record.token_id.eq_ignore_ascii_case(token_id) =>
            {
                return Ok(Some(record));
            }
            Ok(_) => {}
            Err(error) => match error.downcast_ref::<std::io::Error>() {
                // Gone since the directory was listed: no purchase to find.
                Some(io) if io.kind() == std::io::ErrorKind::NotFound => {}
                Some(_) => return Err(error),
                None => tracing::warn!(
                    path = %path.display(),
                    error = %format!("{error:#}"),
                    "purchase ledger record invalid; skipped"
                ),
            },
        }
    }
    Ok(None)
}

#[cfg(test)]
fn runtime_purchase_lock_test_state() -> &'static StdMutex<HashMap<PathBuf, (usize, bool)>> {
    RUNTIME_PURCHASE_LOCK_TEST_STATE.get_or_init(|| StdMutex::new(HashMap::new()))
}

pub(crate) fn persist_runtime_custody_purchase(
    data_dir: &Path,
    purchase: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<()> {
    let lock_path = runtime_purchase_lock_path(data_dir, &purchase.principal_id);
    #[cfg(unix)]
    if let Some(parent) = lock_path.parent() {
        ensure_owner_only_runtime_storage_parent(parent)?;
    }
    #[cfg(not(unix))]
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = ExclusiveFileLock::acquire(&lock_path)?;
    #[cfg(test)]
    let _lock_test_probe = RuntimePurchaseLockTestProbe::enter(lock_path.clone());
    write_owner_only_bytes(
        &runtime_purchase_path(
            data_dir,
            &purchase.principal_id,
            parse_mint_id_hex(&purchase.mint_id)?,
        ),
        &serde_json::to_vec(purchase)?,
    )
}

/// Remove `record`'s purchase file under the purchase ledger lock when the
/// record on disk is still the one `still_it` recognises.
fn remove_runtime_custody_purchase_if(
    data_dir: &Path,
    record: &RuntimeCustodyPurchaseRecord,
    still_it: impl FnOnce(&RuntimeCustodyPurchaseRecord) -> bool,
) -> anyhow::Result<bool> {
    let attempt = record;
    let mint_id = parse_mint_id_hex(&attempt.mint_id)?;
    let lock_path = runtime_purchase_lock_path(data_dir, &attempt.principal_id);
    #[cfg(unix)]
    if let Some(parent) = lock_path.parent() {
        ensure_owner_only_runtime_storage_parent(parent)?;
    }
    #[cfg(not(unix))]
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = ExclusiveFileLock::acquire(&lock_path)?;
    #[cfg(test)]
    let _lock_test_probe = RuntimePurchaseLockTestProbe::enter(lock_path.clone());
    // The load refuses a symlink or a hard-linked file exactly as any read
    // does, so a retirement can never be pointed at anything but this record.
    match load_runtime_custody_purchase(data_dir, &attempt.principal_id, mint_id)? {
        Some(current) if still_it(&current) => {}
        _ => return Ok(false),
    }
    let path = runtime_purchase_path(data_dir, &attempt.principal_id, mint_id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn parse_mint_id_hex(value: &str) -> anyhow::Result<Digest32> {
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

/// Content kind discriminant on the viewer open response.
///
/// A viewer must never have to infer the shape of the session it just opened
/// from which optional geometry fields happen to be present: the media
/// response carries `mime_type`/`codecs`/`has_init_segment`/`segment_count`,
/// and the object response (deferred with the object open path) carries its own
/// chunk geometry instead. This field names the kind outright so each viewer
/// can fail closed on the other one — `capsules/elacity-player` rejects
/// anything but `"media"`.
pub(crate) const RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA: &str = "media";

/// Object twin of [`RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA`].
pub(crate) const RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_OBJECT: &str = "object";

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
pub(crate) fn ensure_owner_only_runtime_storage_parent(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

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
        // A sibling writer racing to bootstrap the same directory chain (for
        // example, another principal's first purchase creating the shared
        // `runtime-purchases/` root) may have created this exact level
        // between our existence check above and this call. Create with mode
        // 0700 atomically (the same idiom `create_owner_only_directory` uses
        // elsewhere in this codebase) rather than `mkdir` then `chmod`: a
        // losing racer's `AlreadyExists` is only ever returned after the
        // winner's `mkdir(..., 0700)` has already completed in the kernel,
        // so there is no window where the directory briefly has loose
        // default permissions for the validation pass below to observe.
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
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

pub(crate) fn write_owner_only_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
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
        options
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
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
